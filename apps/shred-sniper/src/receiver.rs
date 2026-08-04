use {
    crate::metrics::QueueMetrics,
    solana_streamer::{
        packet::{Meta, PACKETS_PER_BATCH, Packet},
        recvmmsg::recv_mmsg,
    },
    std::{
        error::Error,
        io::ErrorKind,
        net::UdpSocket,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
            mpsc,
        },
        thread,
        time::Duration,
    },
    tracing::{debug, info_span, warn},
};

/// `recvmmsg` is called with `MSG_WAITFORONE`, so it returns as soon as the
/// first datagram is ready and takes whatever else is already queued behind it.
/// A full batch is therefore a ceiling rather than something we wait for: at
/// line rate it collapses 64 syscalls into one, and on a quiet socket it costs
/// exactly what a single `recv_from` used to.
const RECV_BATCH: usize = PACKETS_PER_BATCH;

/// Batches a receiver may hold before it has to allocate. Deep enough to ride
/// out a hiccup in the parser, shallow enough that the steady state is a
/// handful of buffers going back and forth.
const POOL_BATCHES: usize = 4;

/// `recvmmsg` blocks until a datagram lands, so without a timeout the exit flag
/// would only be noticed the next time the leader sends us something.
const RECV_TIMEOUT: Duration = Duration::from_secs(1);

/// Datagrams travelling from a receiver thread to the parser, and then back to
/// be refilled. Handing the buffers back is what keeps the hot path free of the
/// allocation the old one-datagram-per-message channel paid on every packet,
/// without trading it for the ~80 KiB of zeroing a fresh batch would cost.
pub struct Batch {
    packets: Vec<Packet>,
    filled: usize,
    /// Which receiver to hand this buffer back to, so a slow socket cannot
    /// drain a fast one's pool.
    socket: usize,
}

impl Batch {
    fn new(socket: usize) -> Self {
        Self {
            packets: vec![Packet::default(); RECV_BATCH],
            filled: 0,
            socket,
        }
    }

    pub fn received(&self) -> &[Packet] {
        &self.packets[..self.filled]
    }

    /// `recv_mmsg` expects every `Meta` to be untouched, so clearing what the
    /// last fill wrote is precisely what makes the buffer reusable.
    fn clear(&mut self) {
        for packet in &mut self.packets[..self.filled] {
            *packet.meta_mut() = Meta::default();
        }
        self.filled = 0;
    }
}

/// The receiving half of the sniper: threads filling batches, and the way back
/// for the buffers once the parser is done with them.
pub struct Receivers {
    /// Filled batches, in whatever order the receiver threads finish them.
    pub batches: mpsc::Receiver<Batch>,
    pub pool: Pool,
    /// Local ports of the TVU sockets, which is what the kernel drop counters
    /// are keyed by. Short of a socket whose address could not be read.
    pub tvu_ports: Vec<u16>,
}

/// The buffers' way home.
pub struct Pool {
    recyclers: Vec<mpsc::Sender<Batch>>,
}

impl Pool {
    /// Hands a drained batch back to the receiver it came from. A receiver that
    /// has already exited just means the buffer is dropped, which is what
    /// shutdown is supposed to look like.
    pub fn recycle(&self, mut batch: Batch) {
        let socket = batch.socket;
        batch.clear();
        let _ = self.recyclers[socket].send(batch);
    }
}

/// Starts one thread per TVU socket, each with a pool of its own.
pub fn spawn(
    sockets: Vec<UdpSocket>,
    exit: Arc<AtomicBool>,
    metrics: Arc<QueueMetrics>,
) -> Result<Receivers, Box<dyn Error>> {
    let (sender, batches) = mpsc::channel::<Batch>();
    let mut recyclers = Vec::new();
    let mut tvu_ports = Vec::new();

    for (index, socket) in sockets.into_iter().enumerate() {
        socket
            .set_read_timeout(Some(RECV_TIMEOUT))
            .map_err(|err| format!("read timeout on tvu socket {index}: {err}"))?;
        match socket.local_addr() {
            Ok(addr) => tvu_ports.push(addr.port()),
            // Only costs us the kernel drop counter for this socket, which is
            // not worth refusing to start over.
            Err(err) => {
                warn!(socket = index, %err, "no local address, drops will be under-counted")
            }
        }

        let (recycler, recycled) = mpsc::channel::<Batch>();
        for _ in 0..POOL_BATCHES {
            recycler
                .send(Batch::new(index))
                .expect("pool receiver is still in scope");
        }
        recyclers.push(recycler);

        let sender = sender.clone();
        let exit = exit.clone();
        let metrics = metrics.clone();
        thread::Builder::new()
            .name(format!("tvu-rx-{index}"))
            .spawn(move || receive(socket, index, recycled, sender, exit, metrics))
            .map_err(|err| format!("failed to spawn tvu reader thread {index}: {err}"))?;
    }
    // The parser's loop ends when every receiver has hung up, which cannot
    // happen while this clone is still around.
    drop(sender);

    Ok(Receivers {
        batches,
        pool: Pool { recyclers },
        tvu_ports,
    })
}

fn receive(
    socket: UdpSocket,
    index: usize,
    recycled: mpsc::Receiver<Batch>,
    sender: mpsc::Sender<Batch>,
    exit: Arc<AtomicBool>,
    metrics: Arc<QueueMetrics>,
) {
    let span = info_span!("tvu_rx", socket = index);
    let _guard = span.enter();
    // A batch the kernel left empty is still clean, so it is kept here rather
    // than round-tripped through the pool.
    let mut spare: Option<Batch> = None;

    while !exit.load(Ordering::Relaxed) {
        // An exhausted pool means the parser is behind. Allocating instead of
        // waiting keeps the socket drained, and the extra buffer joins the pool
        // once it comes back.
        let mut batch = spare
            .take()
            .or_else(|| recycled.try_recv().ok())
            .unwrap_or_else(|| {
                metrics.pool_exhausted();
                Batch::new(index)
            });

        match recv_mmsg(&socket, &mut batch.packets) {
            Ok(0) => spare = Some(batch),
            Ok(filled) => {
                batch.filled = filled;
                metrics.pushed(filled as u64);
                if sender.send(batch).is_err() {
                    debug!("parser dropped, shutting down");
                    break;
                }
            }
            // The read timeout firing on a quiet socket is how the exit flag
            // gets looked at, not something to report.
            Err(err) => {
                if !matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) {
                    debug!(%err, "recvmmsg failed");
                }
                spare = Some(batch);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `recv_mmsg` asserts that every `Meta` handed to it is untouched, so a
    /// batch coming back from the parser has to be indistinguishable from a
    /// fresh one or refilling it trips the assert on a debug build.
    #[test]
    fn a_recycled_batch_looks_untouched() {
        let mut batch = Batch::new(0);
        for packet in batch.packets.iter_mut().take(3) {
            packet.meta_mut().size = 1232;
            packet.meta_mut().port = 8001;
        }
        batch.filled = 3;
        assert_eq!(batch.received().len(), 3);

        batch.clear();

        assert_eq!(batch.filled, 0);
        assert!(batch.received().is_empty());
        assert!(
            batch
                .packets
                .iter()
                .all(|packet| packet.meta() == &Meta::default())
        );
    }
}

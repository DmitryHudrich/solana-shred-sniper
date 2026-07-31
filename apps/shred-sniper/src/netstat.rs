//! Kernel-side receive drops, read out of procfs.
//!
//! An overflowing socket receive buffer is the one failure that leaves no trace
//! in anything we count ourselves: the datagrams never reach userspace, so our
//! packet counters simply read lower and a saturated sniper looks exactly like
//! a quiet network. The kernel does count them, per socket, and procfs is where
//! it says so.

use std::{fs, io};

/// IPv6 sockets keep their own table, and a dual-stack bind appears only there.
const TABLES: [&str; 2] = ["/proc/net/udp", "/proc/net/udp6"];

// Column positions in a procfs UDP row. `tx_queue:rx_queue` and `tr:tm->when`
// are each written as one colon-joined field, so these are not where the
// header's word count would put them.
const LOCAL_ADDRESS: usize = 1;
const DROPS: usize = 12;

/// Datagrams the kernel dropped on the sockets bound to `ports`, cumulative
/// since those sockets were created.
pub fn drops(ports: &[u16]) -> io::Result<u64> {
    let mut total = 0;
    for table in TABLES {
        match fs::read_to_string(table) {
            Ok(contents) => total += sum_drops(&contents, ports),
            // A kernel built without IPv6 has no udp6 table. That is not a
            // failure to report drops, it is an absence of sockets to report.
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(total)
}

fn sum_drops(table: &str, ports: &[u16]) -> u64 {
    table
        .lines()
        .skip(1)
        .filter_map(|row| row_drops(row, ports))
        .sum()
}

fn row_drops(row: &str, ports: &[u16]) -> Option<u64> {
    let mut fields = row.split_whitespace();
    let local = fields.nth(LOCAL_ADDRESS)?;
    // The address is hex, and only the port half identifies us: the address
    // half is the wildcard bind for every socket we own.
    let port = u16::from_str_radix(local.rsplit_once(':')?.1, 16).ok()?;
    if !ports.contains(&port) {
        return None;
    }
    fields.nth(DROPS - LOCAL_ADDRESS - 1)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim procfs, header included. Ports 0x1F90 = 8080, 0x22B8 = 8888.
    const TABLE: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
 3450: 00000000:1F90 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 41521 2 0000000000000000 17
 3451: 0100007F:22B8 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 41522 2 0000000000000000 4
 3452: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 41523 2 0000000000000000 9000
";

    /// The drops column sits past two fields that each contain a colon, so
    /// counting words off the header lands on the wrong one.
    #[test]
    fn reads_the_drops_column_for_our_ports_only() {
        assert_eq!(sum_drops(TABLE, &[8080]), 17);
        assert_eq!(sum_drops(TABLE, &[8888]), 4);
        assert_eq!(sum_drops(TABLE, &[8080, 8888]), 21);
        assert_eq!(
            sum_drops(TABLE, &[53]),
            9000,
            "a port we do not own must not be counted, but must still parse"
        );
        assert_eq!(sum_drops(TABLE, &[]), 0);
    }

    /// procfs is a kernel interface, not a contract we control, so a row we
    /// cannot make sense of has to be skipped rather than poison the total.
    #[test]
    fn survives_rows_it_cannot_parse() {
        let mangled = format!("{TABLE}garbage\n 3453: nocolon 00000000:0000\n");
        assert_eq!(sum_drops(&mangled, &[8080]), 17);
    }
}

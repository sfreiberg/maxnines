//! Running totals, such as packets dropped since an interface came up, which are
//! sent as the change since the last reading. The server works out rates from
//! those changes.

use std::ops::Sub;

/// How much a running total grew since `last`. One that went backwards started
/// again, as after a restart or when a counter wraps, which counts as no change.
pub fn change<T>(last: T, total: T) -> T
where
    T: Copy + PartialOrd + Sub<Output = T> + Default,
{
    if total < last {
        T::default()
    } else {
        total - last
    }
}

/// One running total's last reading, which turns the next into a change.
#[derive(Debug, Default)]
pub struct Change(Option<u64>);

impl Change {
    /// The change since the last reading. The first has nothing to compare with,
    /// and nor does one after a reading that was missing.
    pub fn update(&mut self, total: Option<u64>) -> Option<u64> {
        let change = self.0.zip(total).map(|(last, total)| change(last, total));
        self.0 = total;
        change
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_total_that_went_backwards_is_no_change() {
        assert_eq!(change(10_u64, 15), 5);
        assert_eq!(change(10_u64, 3), 0);
        assert_eq!(change(1.5, 4.0), 2.5);
        assert_eq!(change(4.0, 1.5), 0.0);
    }

    #[test]
    fn change_is_measured_from_the_previous_reading() {
        let mut change = Change::default();
        assert_eq!(change.update(Some(100)), None);
        assert_eq!(change.update(Some(150)), Some(50));
        assert_eq!(change.update(Some(120)), Some(0));
        assert_eq!(change.update(None), None);
        assert_eq!(change.update(Some(130)), None);
        assert_eq!(change.update(Some(140)), Some(10));
    }
}

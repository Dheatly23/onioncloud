//! String parsing utilities.

use chrono::{NaiveDate, NaiveTime};

/// Parse fingerprint in form of 40-digit hexadecimal string.
pub(crate) fn parse_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    // Check if byte length is valid
    let s = s.as_bytes();
    if s.len() != N * 2 {
        return None;
    }

    // Process bytes
    let mut ret = [0u8; N];
    for (i, o) in ret.iter_mut().enumerate() {
        let i = i * 2;
        let (u, l) = (
            char::from(s[i]).to_digit(16)?,
            char::from(s[i + 1]).to_digit(16)?,
        );
        *o = l as u8 | ((u as u8) << 4);
    }

    Some(ret)
}

/// Parse date in form of `YYYY-MM-DD`.
pub(crate) fn parse_date(s: &str) -> Option<NaiveDate> {
    // Extremely naive month and day parsing :)
    let [
        s @ ..,
        b'-',
        mt @ b'0'..=b'9',
        md @ b'0'..=b'9',
        b'-',
        dt @ b'0'..=b'9',
        dd @ b'0'..=b'9',
    ] = s.as_bytes()
    else {
        return None;
    };
    let month = (mt - b'0') * 10 + (md - b'0');
    let day = (dt - b'0') * 10 + (dd - b'0');

    // Year must be at least 4 digits
    if s.len() < 4 {
        return None;
    }

    let mut year = 0i32;
    for &c in s {
        let c @ b'0'..=b'9' = c else { return None };
        year = year.checked_mul(10)?.checked_add((c - b'0').into())?;
    }

    NaiveDate::from_ymd_opt(year, month.into(), day.into())
}

/// Parse time in form of `HH:MM:SS`.
pub(crate) fn parse_time(s: &str) -> Option<NaiveTime> {
    // Extremely naive hour, minute, and second parsing :)
    let [
        ht @ b'0'..=b'2',
        hd @ b'0'..=b'9',
        b':',
        mt @ b'0'..=b'5',
        md @ b'0'..=b'9',
        b':',
        st @ b'0'..=b'5',
        sd @ b'0'..=b'9',
    ] = s.as_bytes()
    else {
        return None;
    };
    let hour = (ht - b'0') * 10 + (hd - b'0');
    let minute = (mt - b'0') * 10 + (md - b'0');
    let second = (st - b'0') * 10 + (sd - b'0');

    NaiveTime::from_hms_opt(hour.into(), minute.into(), second.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::{Datelike as _, Timelike as _};
    use proptest::prelude::*;

    use crate::crypto::relay::RelayId;
    use crate::util::print_hex;

    #[test]
    fn test_parse_date_empty_string_fail() {
        if let Some(v) = parse_date("") {
            panic!("parser expected to fail, got {v}");
        }
    }

    #[test]
    fn test_parse_time_empty_string_fail() {
        if let Some(v) = parse_time("") {
            panic!("parser expected to fail, got {v}");
        }
    }

    proptest! {
        #[test]
        fn test_parse_date(date in (-366i32..).prop_filter_map("invalid date", |t| NaiveDate::from_num_days_from_ce_opt(t).filter(|v| v.year() >= 0))) {
            let s = format!("{:04}-{:02}-{:02}", date.year(), date.month(), date.day());
            let res = parse_date(&s).unwrap();
            assert_eq!(res, date);
        }

        #[test]
        fn test_parse_time(time in (..86400u32).prop_filter_map("invalid time", |t| NaiveTime::from_num_seconds_from_midnight_opt(t, 0))) {
            let s = format!("{:02}:{:02}:{:02}", time.hour(), time.minute(), time.second());
            let res = parse_time(&s).unwrap();
            assert_eq!(res, time);
        }

        #[test]
        fn test_parse_date_fail(s in prop_oneof![
            // Truncate year
            (0..1000u16, 1..13u8, 1..32u8, ..4usize).prop_map(|(y, m, d, w)| format!("{y:0w$}-{m:02}-{d:02}")),
            // Truncate month
            (0..9999u16, 1..10u8, 1..32u8).prop_map(|(y, m, d)| format!("{y:04}-{m}-{d:02}")),
            // Truncate day
            (0..9999u16, 1..13u8, 1..10u8).prop_map(|(y, m, d)| format!("{y:04}-{m:02}-{d}")),
            // Missing year
            (1..13u8, 1..32u8, any::<bool>()).prop_map(|(m, d, s)| format!("{}{m:02}-{d:02}", if s { "-" } else { "" })),
            // Missing month
            (0..9999u16, 1..32u8, any::<bool>(), any::<bool>()).prop_map(|(y, d, s1, s2)| format!("{y:04}{}{}{d:02}", if s1 { "-" } else { "" }, if s2 { "-" } else { "" })),
            // Missing day
            (0..9999u16, 1..13u8, any::<bool>()).prop_map(|(y, m, s)| format!("{y:04}-{m:02}{}", if s { "-" } else { "" })),
            // Year overflow
            (i32::MAX as u64 + 1.., 1..13u8, 1..32u8).prop_map(|(y, m, d)| format!("{y}-{m:02}-{d:02}")),
        ]) {
            if let Some(v) = parse_date(&s) {
                panic!("parser expected to fail, got {v}");
            }
        }

        #[test]
        fn test_parse_time_fail(s in prop_oneof![
            // Truncate hour
            (0..10u8, 0..60u8, 0..60u8).prop_map(|(h, m, s)| format!("{h}:{m:02}:{s:02}")),
            // Truncate minute
            (0..24u8, 0..10u8, 0..60u8).prop_map(|(h, m, s)| format!("{h:02}:{m}:{s:02}")),
            // Truncate second
            (0..24u8, 0..60u8, 0..10u8).prop_map(|(h, m, s)| format!("{h:02}:{m:02}:{s}")),
            // Missing hour
            (0..60u8, 0..60u8, any::<bool>()).prop_map(|(m, s, t)| format!("{}{m:02}:{s:02}", if t { ":" } else { "" })),
            // Missing minute
            (0..24u8, 0..60u8, any::<bool>(), any::<bool>()).prop_map(|(h, s, t1, t2)| format!("{h:02}{}{}{s:02}", if t1 { ":" } else { "" }, if t2 { ":" } else { "" })),
            // Missing second
            (0..24u8, 0..60u8, any::<bool>()).prop_map(|(h, m, t)| format!("{h:02}:{m:02}{}", if t { ":" } else { "" })),
        ]) {
            if let Some(v) = parse_time(&s) {
                panic!("parser expected to fail, got {v}");
            }
        }

        #[test]
        fn test_parse_fingerprint(s in "[0-9A-Fa-f]{40}") {
            let _: RelayId = parse_hex(&s).unwrap();
        }

        #[test]
        fn test_parse_fingerprint_truncated(s in "[0-9A-Fa-f]{0,39}") {
            let v: Option<RelayId> = parse_hex(&s);
            if let Some(v) = v {
                panic!("parser expected to fail, got {}", print_hex(&v));
            }
        }
    }
}

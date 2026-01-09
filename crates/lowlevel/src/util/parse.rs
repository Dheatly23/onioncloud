//! String parsing utilities.

use chrono::{NaiveDate, NaiveTime};

/// Parse date in form of `YYYY-MM-DD`.
pub(crate) fn parse_date(s: &str) -> Option<NaiveDate> {
    let mut i = 0;
    loop {
        match s.as_bytes().get(i)? {
            b'-' if i >= 4 => break,
            b'0'..=b'9' => i += 1,
            _ => return None,
        }
    }

    let year = s[..i].parse::<i32>().ok()?;
    // Extremely naive month and day parsing :)
    let [
        mt @ b'0'..=b'9',
        md @ b'0'..=b'9',
        b'-',
        dt @ b'0'..=b'9',
        dd @ b'0'..=b'9',
    ] = &s.as_bytes()[i + 1..]
    else {
        return None;
    };
    let month = (mt - b'0') * 10 + (md - b'0');
    let day = (dt - b'0') * 10 + (dd - b'0');

    NaiveDate::from_ymd_opt(year, month.into(), day.into())
}

/// Parse time in form of `HH:MM:SS`.
pub(crate) fn parse_time(s: &str) -> Option<NaiveTime> {
    // Extremely naive hour, minute, and second parsing :)
    let [
        ht @ b'0'..=b'9',
        hd @ b'0'..=b'9',
        b':',
        mt @ b'0'..=b'9',
        md @ b'0'..=b'9',
        b':',
        st @ b'0'..=b'9',
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
        fn test_parse_date(date in (0i32..).prop_filter_map("invalid date", NaiveDate::from_num_days_from_ce_opt)) {
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
    }
}

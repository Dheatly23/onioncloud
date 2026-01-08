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
    }
}

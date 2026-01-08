//! String parsing utilities.

use chrono::{NaiveDate, NaiveTime};

/// Parse date in form of `YYYY-MM-DD`.
pub(crate) fn parse_date(s: &str) -> Option<NaiveDate> {
    let mut i = 0;
    loop {
        match s.as_bytes().get(i)? {
            b'-' if i < 4 => break,
            b'0' if i == 0 => return None,
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

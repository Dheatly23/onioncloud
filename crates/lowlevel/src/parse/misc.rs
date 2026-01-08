//! Helper functions for netdoc parsing.

use chrono::{DateTime, NaiveDateTime, Utc};

use super::netdoc::Arguments;
use crate::util::parse::{parse_date, parse_time};

pub(crate) fn args_date_time(args: &mut Arguments<'_>) -> Option<DateTime<Utc>> {
    let date = args.next()?;
    let time = args.next()?;

    Some(NaiveDateTime::new(parse_date(date)?, parse_time(time)?).and_utc())
}

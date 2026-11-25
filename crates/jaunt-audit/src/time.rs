use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_MILLIS: i64 = 253_402_300_799_999;
const MILLIS_PER_SECOND: i64 = 1000;
pub(crate) const SECONDS_PER_DAY: i64 = 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TimeError {
    #[error("the time is outside the supported range")]
    OutOfRange,
    #[error("the time is not an RFC 3339 UTC timestamp")]
    Malformed,
}

impl Timestamp {
    pub fn from_millis(millis: i64) -> Result<Timestamp, TimeError> {
        if (0..=MAX_MILLIS).contains(&millis) {
            Ok(Timestamp(millis))
        } else {
            Err(TimeError::OutOfRange)
        }
    }

    pub fn now() -> Timestamp {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|elapsed| i64::try_from(elapsed.as_millis()).ok())
            .unwrap_or(0);
        Timestamp(millis.clamp(0, MAX_MILLIS))
    }

    pub fn millis(self) -> i64 {
        self.0
    }

    pub fn minus_days(self, days: u32) -> Timestamp {
        let span = i64::from(days) * SECONDS_PER_DAY * MILLIS_PER_SECOND;
        Timestamp((self.0 - span).max(0))
    }

    pub fn parse(text: &str) -> Result<Timestamp, TimeError> {
        let bytes = text.as_bytes();
        if bytes.len() < 20 || !text.is_ascii() {
            return Err(TimeError::Malformed);
        }
        let digits = |range: std::ops::Range<usize>| -> Result<i64, TimeError> {
            let part = bytes.get(range).ok_or(TimeError::Malformed)?;
            if part.is_empty() || !part.iter().all(u8::is_ascii_digit) {
                return Err(TimeError::Malformed);
            }
            part.iter()
                .try_fold(0i64, |acc, digit| {
                    acc.checked_mul(10)?.checked_add(i64::from(digit - b'0'))
                })
                .ok_or(TimeError::Malformed)
        };
        let separators = [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')];
        if separators.iter().any(|(at, want)| bytes[*at] != *want) {
            return Err(TimeError::Malformed);
        }
        let (year, month, day) = (digits(0..4)?, digits(5..7)?, digits(8..10)?);
        let (hour, minute, second) = (digits(11..13)?, digits(14..16)?, digits(17..19)?);
        if !(1..=12).contains(&month)
            || day < 1
            || day > days_in_month(year, month)
            || hour > 23
            || minute > 59
            || second > 59
        {
            return Err(TimeError::Malformed);
        }
        let mut cursor = 19;
        let mut millis = 0;
        if bytes[cursor] == b'.' {
            let start = cursor + 1;
            let end = bytes[start..]
                .iter()
                .position(|byte| !byte.is_ascii_digit())
                .map_or(bytes.len(), |offset| start + offset);
            if end == start || end - start > 9 {
                return Err(TimeError::Malformed);
            }
            let mut fraction = bytes[start..end.min(start + 3)].to_vec();
            while fraction.len() < 3 {
                fraction.push(b'0');
            }
            millis = fraction
                .iter()
                .fold(0, |acc, digit| acc * 10 + i64::from(digit - b'0'));
            cursor = end;
        }
        if &bytes[cursor..] != b"Z" {
            return Err(TimeError::Malformed);
        }
        let days = days_from_civil(year, month, day);
        let seconds = days * SECONDS_PER_DAY + hour * 3600 + minute * 60 + second;
        Timestamp::from_millis(seconds * MILLIS_PER_SECOND + millis)
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let seconds = self.0.div_euclid(MILLIS_PER_SECOND);
        let millis = self.0.rem_euclid(MILLIS_PER_SECOND);
        let (year, month, day) = civil_from_days(seconds.div_euclid(SECONDS_PER_DAY));
        let in_day = seconds.rem_euclid(SECONDS_PER_DAY);
        write!(
            f,
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
            in_day / 3600,
            in_day % 3600 / 60,
            in_day % 60
        )
    }
}

fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let shifted_month = (month + 9) % 12;
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

pub(crate) fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::{TimeError, Timestamp};

    #[test]
    fn known_instants_format_to_rfc3339_with_milliseconds_and_parse_back() {
        for (millis, text) in [
            (0, "1970-01-01T00:00:00.000Z"),
            (1, "1970-01-01T00:00:00.001Z"),
            (951_782_400_000, "2000-02-29T00:00:00.000Z"),
            (1_700_000_000_123, "2023-11-14T22:13:20.123Z"),
            (4_107_542_400_000, "2100-03-01T00:00:00.000Z"),
            (253_402_300_799_999, "9999-12-31T23:59:59.999Z"),
        ] {
            let stamp = Timestamp::from_millis(millis).unwrap();
            assert_eq!(stamp.to_string(), text);
            assert_eq!(Timestamp::parse(text), Ok(stamp), "{text}");
        }
    }

    #[test]
    fn parsing_accepts_short_and_long_fractions_and_nothing_but_utc() {
        assert_eq!(
            Timestamp::parse("2023-11-14T22:13:20Z").unwrap().millis(),
            1_700_000_000_000
        );
        assert_eq!(
            Timestamp::parse("2023-11-14T22:13:20.5Z").unwrap().millis(),
            1_700_000_000_500
        );
        assert_eq!(
            Timestamp::parse("2023-11-14T22:13:20.123456789Z")
                .unwrap()
                .millis(),
            1_700_000_000_123
        );
        for bad in [
            "",
            "2023-11-14",
            "2023-11-14T22:13:20",
            "2023-11-14T22:13:20+00:00",
            "2023-11-14 22:13:20Z",
            "2023-13-14T22:13:20Z",
            "2023-02-29T00:00:00Z",
            "2023-11-14T24:00:00Z",
            "2023-11-14T22:60:00Z",
            "2023-11-14T22:13:60Z",
            "2023-11-14T22:13:20.Z",
            "2023-11-14T22:13:20.1234567890Z",
            "+023-11-14T22:13:20Z",
            "2023-11-14T22:13:20Zx",
            "２023-11-14T22:13:20Z",
        ] {
            assert_eq!(Timestamp::parse(bad), Err(TimeError::Malformed), "{bad}");
        }
        assert_eq!(
            Timestamp::parse("1969-12-31T23:59:59Z"),
            Err(TimeError::OutOfRange)
        );
    }

    #[test]
    fn the_supported_range_is_enforced_and_days_can_be_subtracted() {
        assert_eq!(Timestamp::from_millis(-1), Err(TimeError::OutOfRange));
        assert_eq!(
            Timestamp::from_millis(253_402_300_800_000),
            Err(TimeError::OutOfRange)
        );
        let stamp = Timestamp::from_millis(10 * 86_400_000 + 5).unwrap();
        assert_eq!(stamp.minus_days(3).millis(), 7 * 86_400_000 + 5);
        assert_eq!(stamp.minus_days(100).millis(), 0);
    }
}

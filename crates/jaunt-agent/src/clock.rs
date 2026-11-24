use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jaunt_tunnel::BoxFuture;

const MAX_NAP: Duration = Duration::from_secs(300);

pub trait Clock: Send + Sync {
    fn now(&self) -> SystemTime;

    fn sleep_until(&self, deadline: SystemTime) -> BoxFuture<'_, ()>;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }

    fn sleep_until(&self, deadline: SystemTime) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            while let Ok(remaining) = deadline.duration_since(SystemTime::now()) {
                if remaining.is_zero() {
                    return;
                }
                tokio::time::sleep(remaining.min(MAX_NAP)).await;
            }
        })
    }
}

pub fn unix_secs(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(elapsed) => i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX),
        Err(before) => i64::try_from(before.duration().as_secs()).map_or(i64::MIN, |secs| -secs),
    }
}

pub fn at_unix_secs(secs: i64) -> SystemTime {
    let secs = u64::try_from(secs).unwrap_or(0);
    UNIX_EPOCH
        .checked_add(Duration::from_secs(secs))
        .unwrap_or(UNIX_EPOCH)
}

pub fn format_utc(unix_secs: i64) -> String {
    let days = unix_secs.div_euclid(86_400);
    let secs_of_day = unix_secs.rem_euclid(86_400);
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs_of_day / 3600,
        secs_of_day % 3600 / 60,
        secs_of_day % 60
    )
}

pub fn compact_utc(unix_secs: i64) -> String {
    format_utc(unix_secs).replace(['-', ':'], "")
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::{at_unix_secs, compact_utc, format_utc, unix_secs};

    #[test]
    fn utc_formatting_covers_epoch_leap_days_and_the_compact_form() {
        for (secs, text) in [
            (0, "1970-01-01T00:00:00Z"),
            (951_782_400, "2000-02-29T00:00:00Z"),
            (1_795_000_000, "2026-11-18T11:06:40Z"),
        ] {
            assert_eq!(format_utc(secs), text);
        }
        assert_eq!(compact_utc(1_795_000_000), "20261118T110640Z");
    }

    #[test]
    fn unix_seconds_round_trip_and_saturate() {
        let time = UNIX_EPOCH + Duration::from_secs(1_795_000_000);
        assert_eq!(unix_secs(time), 1_795_000_000);
        assert_eq!(at_unix_secs(1_795_000_000), time);
        assert_eq!(at_unix_secs(-5), UNIX_EPOCH);
        assert_eq!(unix_secs(UNIX_EPOCH - Duration::from_secs(7)), -7);
    }
}

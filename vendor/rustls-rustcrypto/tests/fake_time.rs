use rustls::pki_types::UnixTime;
use rustls::time_provider::TimeProvider;

#[derive(Debug)]
pub struct FakeTime;

impl TimeProvider for FakeTime {
    fn current_time(&self) -> Option<UnixTime> {
        None
    }
}

use std::process::ExitCode;

fn main() -> ExitCode {
    jaunt_host_users::run(std::env::args_os().skip(1))
}

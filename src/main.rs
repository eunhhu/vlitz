mod core;
mod util;
mod gum;

use core::execute_cli;

fn main() {
    pretty_env_logger::init();
    execute_cli();
}

use super::cli::{PsArgs, Sort};
use frida::{Device, Process};

pub fn ps<'a>(device: &'a Device<'a>, args: &'a PsArgs) -> Vec<Process<'a>> {
    let processes = device.enumerate_processes();
    let mut filtered = processes
        .into_iter()
        .filter(|process| {
            if let Some(name) = &args.filter {
                process
                    .get_name()
                    .to_lowercase()
                    .contains(&name.to_lowercase())
            } else {
                true
            }
        })
        .collect::<Vec<Process>>();
    if args.sort.is_some() {
        match args.sort {
            Some(Sort::Name) => filtered.sort_by(|a, b| {
                a.get_name()
                    .to_lowercase()
                    .cmp(&b.get_name().to_lowercase())
            }),
            Some(Sort::Pid) => filtered.sort_by(|a, b| a.get_pid().cmp(&b.get_pid())),
            None => {}
        }
    }
    return filtered;
}

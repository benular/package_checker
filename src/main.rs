use chrono::Local;
use std::{
    fs::{File, OpenOptions},
    io::Write,
    process::Command,
};
fn main() {
    let mut audit = match OpenOptions::new()
        .create(true)
        .append(true)
        .open(generate_logname())
    {
        Ok(file) => file,
        Err(error) => {
            eprint!("failed to create new audit {}", error);
            return; //smt like break available?
        }
    };
    harden_memory(&mut audit, get_aur_helper());

    // try to run the python file? else reimplement
    // let installed_pkgs=Command::new("pacman").arg("-Q").output();
    // Setup User Best Practices
    setup_user(&mut audit);
}

pub fn get_aur_helper() -> &'static str {
    match Command::new("yay").arg("-V").output() {
        Ok(output) if output.status.success() => "yay",
        _ => match Command::new("paru").arg("-V").output() {
            Ok(output) if output.status.success() => "paru",
            _ => "none",
        },
    }
}

pub fn run_command(line: &str, path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let file = std::fs::read_to_string(path)?;
    if !file.contains(line) {
        let mut echo_command = Command::new("sudo");
        echo_command
            .arg("sh")
            .arg("-c")
            .arg(format!("echo '{}' >> {}", line, path));
        echo_command.status()?;
    }
    Ok(())
}

pub fn setup_user(log: &mut File) {
    // implement user setup best practices from the user tab
    // setting delay after failed login attempts
    if run_command(
        "auth optional pam_faildelay.so delay=3000000",
        "/etc/pam.d/system-login",
    )
    .is_ok()
    {
        let _ = writeln!(log, "added delay after failed login");
    }

    //disable ssh logins for root
    if run_command(
        "PermitRootLogin no",
        "/etc/ssh/sshd_config.d/20-deny-root.conf",
    )
    .is_ok()
    {
        let _ = writeln!(log, "removed root ssh access");
    };

    //limit processes to 7000
    if run_command("soft nproc 7000", "/etc/security/limits.conf").is_ok() {
        let _ = writeln!(log, "added process limit");
    }
}
fn generate_logname() -> String {
    // generates the name of the logfile -> returns for example "audit2025-123-31"
    let date = Local::now().format("%Y-%m-%d").to_string();
    format!("audit_{}.md", date)
}

//TODO: before implementation test hardend_malloc to check for issues and chrashes(seems to crash
//frequently with firefox, docker steam and wine)
// TODO: Function that lets the user either decide per package case if hardend_malloc should be
// used or not(depending on installed_pkgs)
pub fn harden_memory(log: &mut File, aur_helper: &str) {}
//TODO reencrypt the boot drive -> needs test env!
pub fn encrypt_drive(audit: &mut File) {}

// TODO install Linux_kernel_hardened, set it to default in bootloader conf (grub or systemd?)
pub fn harden_kernel() {}

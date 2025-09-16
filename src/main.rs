use chrono::Local;
use serde::ser::Error;
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
        Command::new("sudo")
            .arg("sh")
            .arg("-c")
            .arg(format!("echo '{}' >> {}", line, path))
            .status()?;
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

//TODO what if the installations fail? retry? evaluate options more
pub fn harden_memory(log: &mut File, aur_helper: &str) -> Result<(), String> {
    if aur_helper != "none" {
        match Command::new(aur_helper)
            .args(["-S", "hardened_malloc"])
            .status()
        {
            Ok(status) if status.success() => {
                let _ = writeln!(log, "installed hardened_malloc");
                Ok(())
            }
            Ok(_) => {
                let _ = writeln!(log, "memory hardening via aur helper failed: non-zero exit");
                Err("AUR helper installation failed".to_string())
            }
            Err(error) => {
                let _ = writeln!(log, "memory hardening via aur helper failed - {}", error);
                Err(format!("AUR helper command error: {}", error))
            }
        }
    } else {
        //TODO look into adding a loadingbar? could be interestion to look into multithreading
        println!("no aur helper found, using makepkg, this takes longer");
        match Command::new("git")
            .args(["clone", "https://aur.archlinux.org/hardened_malloc.git"])
            .status()
        {
            Ok(status) if status.success() => {
                std::env::set_current_dir("hardened_malloc");
                match Command::new("makepkg").arg("-sri").status() {
                    Ok(compiled) if compiled.success() => {
                        let _ = writeln!(log, "hardened_malloc installed via makepkg");
                        Ok(())
                    }
                    Ok(_) => {
                        let _ = writeln!(log, "makepkg failed: non-zero exit");
                        Err("makepkg failed non-zero exit".to_string())
                    }
                    Err(error) => {
                        let _ = writeln!(log, "makepkg failed {}", error);
                        Err(format!("Makepkg errors: {}", error))
                    }
                }
            }
            Ok(_) => {
                let _ = writeln!(log, "failed to clone repo: non zero exit");
                Err("failed to clone repo: non zero exit".to_string())
            }
            Err(error) => {
                let _ = writeln!(log, "failed to clone hardened_malloc: {}", error);
                Err(format!("failed to clone: {}", error))
            }
        }
    }
}
//TODO reencrypt the boot drive -> needs test env!
pub fn encrypt_drive(audit: &mut File) {}

// TODO install Linux_kernel_hardened, set it to default in bootloader conf (grub or systemd?)
pub fn harden_kernel() {}

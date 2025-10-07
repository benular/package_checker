use chrono::Local;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    process::Command,
};
mod configure_firewall;

fn execute_command_with_logging(
    log: &mut File,
    command: &str,
    args: &[&str],
    success_msg: &str,
    error_msg: &str,
) -> Result<(), String> {
    match Command::new(command).args(args).status() {
        Ok(status) if status.success() => {
            let _ = writeln!(log, "{}", success_msg);
            Ok(())
        }
        Ok(_) => {
            let _ = writeln!(log, "{}: command returned non-zero exit code", error_msg);
            Err(error_msg.to_string())
        }
        Err(e) => {
            let _ = writeln!(log, "{}: failed to execute command: {}", error_msg, e);
            Err(format!("{}: {}", error_msg, e))
        }
    }
}

fn main() {
    let mut audit = match OpenOptions::new()
        .create(true)
        .append(true)
        .open(generate_logname())
    {
        Ok(file) => file,
        Err(error) => {
            eprintln!("failed to create new audit {}", error);
            return;
        }
    };

    println!("Starting Arch Linux security hardening...");
    let _ = writeln!(audit, "=== Arch Linux Security Hardening Started ===");

    // Memory hardening
    if let Err(e) = harden_memory(&mut audit) {
        eprintln!("Memory hardening failed: {}", e);
    }

    // Install hardened kernel
    if let Err(e) = install_hardened_kernel(&mut audit) {
        eprintln!("Hardened kernel installation failed: {}", e);
    }

    // Restrict kernel pointers
    if let Err(e) = restict_kptr(&mut audit) {
        eprintln!("Kernel pointer restriction failed: {}", e);
    }

    // Install Linux Kernel Runtime Guard
    if let Err(e) = install_kernel_runtime_guard(&mut audit) {
        eprintln!("LKRG installation failed: {}", e);
    }

    // Setup user security best practices
    setup_user(&mut audit);

    // Configure firewall
    if let Err(e) = configure_firewall::setup_firewall(&mut audit) {
        eprintln!("Firewall configuration failed: {}", e);
    }

    let _ = writeln!(audit, "=== Security hardening completed ===");
    println!("Security hardening completed. Check {} for details.", generate_logname());
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
pub fn harden_memory(log: &mut File) -> Result<(), String> {
    //TODO look into adding a loadingbar? could be interestion to look into multithreading
    match Command::new("git")
        .args(["clone", "https://aur.archlinux.org/hardened_malloc.git"])
        .status()
    {
        Ok(status) if status.success() => {
            let _ = std::env::set_current_dir("hardened_malloc");
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
// TODO install Linux_kernel_hardened, set it to default in bootloader conf (grub or systemd?)
pub fn install_hardened_kernel(log: &mut File) -> Result<(), String> {
    match Command::new("pacman")
        .args(["-S", "linux_hardened"])
        .status()
    {
        Ok(status) if status.success() => {
            let _ = writeln!(log, "hardened kernel installed");
            Ok(())
        }
        Ok(_) => {
            let _ = writeln!(log, "linux_hardened installation failed: non-zero exit ");
            Err("linux_hardened installtation failed: non-zero exit".to_string())
        }
        Err(error) => {
            let _ = writeln!(log, "linux_hardened installation failed {}", error);
            Err(format!("linux_hardened installtation failed: {}", error))
        }
    }
}

pub fn restict_kptr(log: &mut File) -> Result<(), String> {
    // restrict access to kernel pointers
    // pattern matching stupid in this case,
    match Command::new("cat")
        .arg("/ect/sysctl.d/51-kptr-restrict.conf")
        .status()
    {
        Ok(status) if status.success() => {
            // unwrap panics on error-> pattern matching would be more resiliant
            let file = fs::read_to_string("/etc/sysctl.d/51-kptr-restrict.conf").unwrap();
            let _ = file.replace("kernel.kptr_restrict=0", "kernel.kptr_restrict=1");
            Ok(())
        }
        Ok(_) => {
            let _ = writeln!(log, "linux_hardened installation failed: non-zero exit ");
            Err("linux_hardened installtation failed: non-zero exit".to_string())
        }
        Err(status) => {
            let _ = writeln!(
                log,
                "failed to cat /ect/sysctl.d/51-kptr-restrict.conf {}",
                status
            );
            Err(format!(
                "failed to cat /etc/sysctl.d/51-kptr-restrict.conf: {}",
                status
            ))
        }
    }
}
pub fn get_aur_helper() -> String {
    let aur_helpers = ["yay", "paru", "trizen", "pikaur", "aurman", "pakku"];

    for helper in &aur_helpers {
        if Command::new("which").arg(helper).status().is_ok() {
            return helper.to_string();
        }
    }

    "none".to_string()
}

fn install_kernel_runtime_guard(log: &mut File) -> Result<(), String> {
    let aur_helper = get_aur_helper();
    if &aur_helper != "none" {
        match Command::new(aur_helper).args(["-S", " lkrg-dkms"]).status() {
            Ok(status) if status.success() => {
                let _ = writeln!(log, "installed Linux Kernel Runtime Guard");
                Ok(())
            }
            Ok(_) => Ok(()),
            Err(status) => {
                let _ = writeln!(
                    log,
                    "aur helper lkrg-dkms installation failed with: {} ",
                    status
                );
                Ok(())
            }
        }
    } else {
        let _ = writeln!(log, "no aur helper installed");
        Ok(())
    }
}

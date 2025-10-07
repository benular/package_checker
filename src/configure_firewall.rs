use std::process::Command;
use std::fs::File;
use std::io::Write;

pub fn setup_firewall(log: &mut File) -> Result<(), String> {
    let _ = writeln!(log, "Starting firewall configuration...");
    
    // Install firewalld
    install_firewalld(log)?;
    
    // Enable and start firewalld service
    enable_firewalld_service(log)?;
    
    // Configure basic firewall rules
    configure_basic_rules(log)?;
    
    let _ = writeln!(log, "Firewall configuration completed");
    Ok(())
}

fn install_firewalld(log: &mut File) -> Result<(), String> {
    match Command::new("pacman").args(["-S", "--noconfirm", "firewalld"]).status() {
        Ok(status) if status.success() => {
            let _ = writeln!(log, "successfully installed firewalld");
            Ok(())
        }
        Ok(_) => {
            let _ = writeln!(log, "failed to install firewalld: pacman returned non-zero exit code");
            Err("Failed to install firewalld".to_string())
        }
        Err(e) => {
            let _ = writeln!(log, "failed to execute pacman: {}", e);
            Err(format!("Failed to execute pacman: {}", e))
        }
    }
}

fn enable_firewalld_service(log: &mut File) -> Result<(), String> {
    // Enable firewalld service
    match Command::new("systemctl").args(["enable", "firewalld"]).status() {
        Ok(status) if status.success() => {
            let _ = writeln!(log, "firewalld service enabled");
        }
        Ok(_) => {
            let _ = writeln!(log, "failed to enable firewalld service: non-zero exit code");
            return Err("Failed to enable firewalld service".to_string());
        }
        Err(e) => {
            let _ = writeln!(log, "failed to enable firewalld service: {}", e);
            return Err(format!("Failed to enable firewalld service: {}", e));
        }
    }

    // Start firewalld service
    match Command::new("systemctl").args(["start", "firewalld"]).status() {
        Ok(status) if status.success() => {
            let _ = writeln!(log, "firewalld service started");
            Ok(())
        }
        Ok(_) => {
            let _ = writeln!(log, "failed to start firewalld service: non-zero exit code");
            Err("Failed to start firewalld service".to_string())
        }
        Err(e) => {
            let _ = writeln!(log, "failed to start firewalld service: {}", e);
            Err(format!("Failed to start firewalld service: {}", e))
        }
    }
}

fn configure_basic_rules(log: &mut File) -> Result<(), String> {
    // Set default zone to drop (more restrictive)
    match Command::new("firewall-cmd").args(["--set-default-zone=drop"]).status() {
        Ok(status) if status.success() => {
            let _ = writeln!(log, "set default firewall zone to drop");
        }
        Ok(_) => {
            let _ = writeln!(log, "failed to set default zone: non-zero exit code");
        }
        Err(e) => {
            let _ = writeln!(log, "failed to set default zone: {}", e);
        }
    }

    // Allow SSH on trusted interfaces (adjust as needed)
    match Command::new("firewall-cmd").args(["--zone=trusted", "--add-service=ssh", "--permanent"]).status() {
        Ok(status) if status.success() => {
            let _ = writeln!(log, "added SSH service to trusted zone");
        }
        Ok(_) => {
            let _ = writeln!(log, "failed to add SSH to trusted zone: non-zero exit code");
        }
        Err(e) => {
            let _ = writeln!(log, "failed to add SSH to trusted zone: {}", e);
        }
    }

    // Reload firewall rules
    match Command::new("firewall-cmd").args(["--reload"]).status() {
        Ok(status) if status.success() => {
            let _ = writeln!(log, "firewall rules reloaded");
            Ok(())
        }
        Ok(_) => {
            let _ = writeln!(log, "failed to reload firewall rules: non-zero exit code");
            Ok(()) // Don't fail the entire setup for this
        }
        Err(e) => {
            let _ = writeln!(log, "failed to reload firewall rules: {}", e);
            Ok(()) // Don't fail the entire setup for this
        }
    }
}


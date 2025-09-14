use std::{fs::{File, OpenOptions}, io::Write, process::Command};
fn main(){
    let mut log= File::create("log.md");

    let installed_pkgs=Command::new("pacman").arg("-Q").output();

 
}

pub fn run_command(line:&str, path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let output =Command::new("cat").arg(&path).output()?;

    let file_content =String::from_utf8(output.stdout)?;
    if !file_content.contains(&line) {
        let mut echo_command = Command::new("sudo");
        echo_command.arg("sh").arg("-c").arg(format!("echo '{}' >> {}", line,path));
        echo_command.status()?;
    }
    Ok(())
}

pub fn  setup_user(){
    // implement user setup best practices from the user tab
    // setting delay after failed login attempts
    let log= OpenOptions::new().create(true).append(true).open(generate__logname());
    if !run_command("auth optional pam_faildelay.so delay=3000000", "/etc/pam.d/system-login").is_err(){
        log.write_fmt("added delay after failed login");
    }
    
    //disable ssh logins for root
    if !run_command("PermitRootLogin no","/etc/ssh/sshd_config.d/20-deny-root.conf" ).is_err(){
        log.write_fmt("removed root ssh access");
    };

    //limit processes
    if !run_command("soft nproc 7000", "/etc/security/limits.conf").is_err(){

    }

}
fn generate__logname()-> &str{
    // generates the name of the logfile -> returns for example "audit2025-123-31"
    let date = Local::now().format("%Y-%m-%d").to_string();
    return ("audit_{}",date)

}
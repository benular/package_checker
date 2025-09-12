use std::process::Command;
//use serde

pub fn disable_root_ssh()-> Result<(), Box <dyn std::error::Error>>{
    let line= "PermitRootLogin no";
    let output=Command::new("cat")
        .arg("/etc/ssh/sshd_config.d/20-deny-root.conf")
        .output()?;
    let file=String.from_utf8(output.stdout)?;
    if !file.contains(line){
        let mut add_line=Command::new("sudo");
        add_line.arg("sh")
                .arg("-c")
                .arg(format!("echo '{}' >>/etc/ssh/sshd_config.d/20-deny-root.conf",line));
    }
    Ok(())

}

pub fn enable_login_delay() -> Result<(), Box<dyn std::error::Error>> {
    let line = "auth optional pam_faildelay.so delay=3 000000";
    let output = Command::new("cat")
        .arg("/etc/pam.d/system-login")
        .output()?;
    let file_content = String::from_utf8(output.stdout)?;
    
    if !file_content.contains(line) {
        let mut echo_command = Command::new("sudo");
        echo_command.arg("sh")
            .arg("-c")
            .arg(format!("echo '{}' >> /etc/pam.d/system-login", line));
        echo_command.status()?;
    }
    Ok(())
}
 

pub fn run_command(line, command, path)->Result>(), Box<dyn sdt::error::Error>>{
    let output=Command::new("cat").args({},path).output()?;
    
    let file_content = String::from_utf8(output.stdout)?;
    
    if !file_content.contains(line) {
        let mut echo_enhancement= Command::new("sudo").arg("sh").arg("-c").arg(format!("echo {} >> {}",path,line))
        
    } 
} 
// fn limit_processes(limit :u16){

// }

mod user_settings;
use std::process::Command;
fn main(){
    let installed_pkgs=Command::new("pacman").args("-Q").output()?;
    if &installed_pkgs.contains("ssh"){
        
    }
    user_settings::enable_login_delay();
}
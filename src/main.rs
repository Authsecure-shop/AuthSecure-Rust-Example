use authsecure_rust::AuthSecure;
use std::io;

fn main() {
    let mut AuthSecureApp = AuthSecure::new(
        "XD", // App Name
        "3ezshCmkXrn", // Owner ID
        "7a8bfeb28afcd690812ee5de010a6860", // Secret
        "1.0", // Version
    );

    println!("Connecting...");
    AuthSecureApp.init();

    loop {
        println!("\n[1] Login\n[2] Register\n[3] License Login\n[4] Exit");
        print!("Choose option: ");
        io::Write::flush(&mut io::stdout()).unwrap();

        let mut choice = String::new();
        io::stdin().read_line(&mut choice).unwrap();
        let choice = choice.trim();

        match choice {
            "1" => {
                let (u, p) = input_credentials();
                AuthSecureApp.login(&u, &p);
            }
            "2" => {
                let (u, p) = input_credentials();
                let l = input("License: ");
                AuthSecureApp.register(&u, &p, &l);
            }
            "3" => {
                let l = input("License: ");
                AuthSecureApp.license_login(&l);
            }
            "4" => {
                println!("Goodbye!");
                break;
            }
            _ => println!("Invalid option!"),
        }
    }
}

fn input(prompt: &str) -> String {
    print!("{}", prompt);
    io::Write::flush(&mut io::stdout()).unwrap();
    let mut val = String::new();
    io::stdin().read_line(&mut val).unwrap();
    val.trim().to_string()
}

fn input_credentials() -> (String, String) {
    let username = input("Username: ");
    let password = input("Password: ");
    (username, password)
}

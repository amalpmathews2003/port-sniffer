use std::env;
use std::io::{self, Write};
use std::net::{IpAddr, TcpStream};
use std::process;
use std::str::FromStr;
use std::sync::mpsc::{channel, Sender};
use std::thread;
use std::time::{Duration, Instant};

const MAX: u16 = 65535;

struct Arguments {
    ip_addr: IpAddr,
    threads: u16,
    start_port: u16,
    last_port: u16,
}

fn get_thread_val(sp: u16, lp: u16) -> u16 {
    if lp - sp < 10 {
        return 1;
    } else if lp - sp < 50 {
        return 5;
    } else if lp - sp < 100 {
        return 10;
    } else if lp - sp < 500 {
        return 50;
    } else if lp - sp < 2000 {
        return 80;
    } else if lp - sp < 10000 {
        return 500;
    } else if lp - sp < 20000 {
        return 700;
    } else if lp - sp < 30000 {
        return 900;
    } else if lp - sp < 40000 {
        return 1000;
    } else if lp - sp < 50000 {
        return 1200;
    } else {
        return 1500;
    }
}

impl Arguments {
    fn new(args: &[String]) -> Result<Arguments, &'static str> {
        if args.len() < 2 {
            return Err("not enought arguments");
        } else if args.len() > 6 {
            return Err("too many arguments");
        } else {
            let t = args[1].clone();
            if let Ok(ip_addr) = IpAddr::from_str(&t) {
                //got a valid ipaddress and no thread is defalut
                let mut start_port: u16 = 0;
                let mut last_port: u16 = MAX;
                if args.len() > 2 {
                    start_port = match args[2].parse::<u16>() {
                        Ok(s) => s,
                        Err(_) => 0,
                    };
                }

                if args.len() > 3 {
                    last_port = match args[3].parse::<u16>() {
                        Ok(s) => s,
                        Err(_) => MAX,
                    };
                }
                return Ok(Arguments {
                    ip_addr,
                    threads: get_thread_val(start_port, last_port),
                    start_port,
                    last_port,
                });
            } else {
                //if flag is passed
                let flag = args[1].clone();
                if flag.contains("-h") || flag.contains("-help") && args.len() == 2 {
                    println!(
                        "Help
                            ................port sniffer.............
                            sniffer 127.0.0.1
                        
                            start_port : default value 0
                            last_port  : default value 65535
                            threads    : default value is according to range of start and last ports
                            
                            thread,start_port,last_port are optional.
                            
                        ex :) sniffer.exe ip start_port? last_port? 
                                sniffer.exe -t threads ip start_port? last_port?
                                
                                sniffer.exe 127.0.0.1 ;scans port 0 to 65535 of 127.0.0.1
                                sniffer.exe -t 1000 127.0.01 ;scans port 0 to 65535 of 127.0.0.1 in 1000 threads
                                sniffer.exe 127.0.01 10 ;scans port 10 to 65535 of 127.0.0.1
                                sniffer.exe 127.0.01 10 100 ;scans port 10 to 100 of 127.0.0.1
                                sniffer.exe -t 200 127.0.01 10 ;scans port 10 to 65535 of 127.0.0.1 in 200 threds
                                sniffer.exe -t 299 127.0.01 10 100 ;scans port 10 to 100 of 127.0.0.1 in 299 threds
                        "
                    );
                    return Err("help");
                } else if flag.contains("-h") || flag.contains("-help") {
                    return Err("too many arguments");
                } else if flag.contains("-t") {
                    //number of thread is passed
                    // .exe -j 1000 127.0.0.1
                    let ip_addr = match IpAddr::from_str(&args[3]) {
                        Ok(s) => s,
                        Err(_) => return Err("not a valid IPADDR, must be ipv4 or ipv6"),
                    };
                    let threads = match args[2].parse::<u16>() {
                        Ok(s) => s,
                        Err(_) => return Err("failed to parse number of threads given"),
                    };
                    let mut start_port: u16 = 0;
                    let mut last_port: u16 = MAX;
                    if args.len() > 4 {
                        start_port = match args[4].parse::<u16>() {
                            Ok(s) => s,
                            Err(_) => 0,
                        };
                    }

                    if args.len() > 5 {
                        last_port = match args[5].parse::<u16>() {
                            Ok(s) => s,
                            Err(_) => MAX,
                        };
                    }
                    return Ok(Arguments {
                        ip_addr,
                        threads,
                        start_port,
                        last_port,
                    });
                } else {
                    return Err("Invalid syntax");
                }
            }
        }
    }
}

fn scan(tx: Sender<u16>, start_port: u16, ip_addr: IpAddr, last_port: u16, threads: u16) {
    let mut port = start_port + 1;
    loop {
        // println!("{}", port);
        match TcpStream::connect((ip_addr, port)) {
            Ok(_) => {
                print!(".");
                io::stdout().flush().unwrap();
                tx.send(port).unwrap();
            }
            Err(_) => {}
        }
        if last_port - port <= threads {
            break;
        }
        port += threads;
    }
}

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let start = Instant::now();
    let arguments = Arguments::new(&args).unwrap_or_else(|err| {
        if err.contains("help") {
            process::exit(0);
        } else {
            eprintln!("{} problem in parsing arguments :{}", program, err);
            process::exit(0);
        }
    });
    println!(
        "Scanning {:?} for ports {} to {} with {} threads",
        arguments.ip_addr, arguments.start_port, arguments.last_port, arguments.threads
    );
    let (tx, rx) = channel();

    for i in 0..arguments.threads {
        let tx = tx.clone();
        thread::spawn(move || {
            scan(
                tx,
                i + arguments.start_port,
                arguments.ip_addr,
                arguments.last_port,
                arguments.threads,
            );
        });
    }
    
    let mut open_ports = vec![];
    drop(tx);
    for p in rx {
        open_ports.push(p);
    }
    println!("");
    open_ports.sort();
    for port in open_ports {
        println!("{} is open", port)
    }
    let duration = start.elapsed();
    println!("Sanning completed in {:?}",duration);
}

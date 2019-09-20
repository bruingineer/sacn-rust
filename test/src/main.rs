extern crate sacn;
use sacn::DmxSource;
use std::{thread, time}; // https://doc.rust-lang.org/std/thread/fn.sleep.html (20/09/2019)

fn main() {
    let dmx_source = DmxSource::with_ip("Controller", "192.168.1.3").unwrap();

    dmx_source.terminate_stream(1);

    let wait_time = time::Duration::from_millis(1);

    loop {
        dmx_source.send(1, &[0, 1, 2]);
        thread::sleep(wait_time);
    }
    

    dmx_source.terminate_stream(1);
}
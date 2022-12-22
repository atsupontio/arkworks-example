
use std::fmt::Write;
pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}


pub fn hexdump(bytes: &[u8]) -> String {

    let mut sum = String::new();

    println!("{} bytes:", bytes.len());
    for (i, b) in bytes.iter().enumerate() {
        // b: &u8 の値を2桁の16進数で表示する
        print!("{:?}", b);
        let a = format!("{:b}", b);
        sum += &a;

        // 値を16個表示するごとに改行する
        if (i + 1) % 16 == 0 {
            println!();
        }
    }
    println!();
    println!("{:?}", sum);
    sum
}
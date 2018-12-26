#![feature(async_await, await_macro, futures_api, pin)]

#[macro_use]
extern crate serde_json;

use sodiumoxide::crypto::{box_, sign::{self, PublicKey, SecretKey}, auth, scalarmult::*, secretbox, hash::sha256};
use std::io;
use std::io::prelude::*;
use std::io::BufReader;
use std::fs;
use std::fs::File;
use dirs::home_dir;
use serde_json::Value;
use std::str;
use std::net::SocketAddr;
use std::str::FromStr;
use futures::task::*;

// use net2::UdpBuilder;
// use net2::unix::UnixUdpBuilderExt;

use byteorder::{BigEndian, WriteBytesExt, ReadBytesExt};

use futures::executor::{self, LocalPool};
use romio::tcp::TcpStream;
use futures::prelude::*;


fn get_keypair() -> io::Result<(PublicKey, SecretKey)> {
    let path = home_dir().expect("Couldn't determine home directory").join(".ssb/secret");
    match File::open(&path) {
        Ok(f) => {
            let json: String = BufReader::new(f)
                .lines()
                .map(|l| l.unwrap())
                .filter(|l| !l.starts_with("#"))
                .collect();

            let v: Value = serde_json::from_str(&json)?;

            let sk = base64::decode(&v["private"].as_str().expect("str").split(".").next().expect(".")).unwrap();
            let pk = base64::decode(&v["public"].as_str().expect("str").split(".").next().expect(".")).unwrap();

            return Ok((PublicKey::from_slice(&pk).expect("pk"), SecretKey::from_slice(&sk).expect("sk")));
        }
        Err(..) => {
            let (pk, sk) = sign::gen_keypair();
            let curve = "ed25519";
            let identity = json!({
                "curve": curve,
                "public": format!("{}.{}", base64::encode(&pk), curve),
                "private": format!("{}.{}", base64::encode(&sk[..]), curve),
                "id": format!("@{}.{}", base64::encode(&pk), curve),
            });
            fs::create_dir_all(path.parent().unwrap())?;
            let mut f = File::create(&path)?;
            f.write_all(&serde_json::to_vec_pretty(&identity).unwrap())?;
            return Ok((pk, sk));
        }
    }
}

#[derive(Debug)]
enum ConnPartConfig {
    // net:
    NetTcp { address: SocketAddr },
    // shs:
    SimpleHandshake { public_key: PublicKey },
}

extern "C" {
    pub fn crypto_sign_ed25519_pk_to_curve25519(
        curve25519_pk: *mut libc::c_uchar,
        ed25519_pk: *const libc::c_uchar,
    ) -> libc::c_int;
    pub fn crypto_sign_ed25519_sk_to_curve25519(
        curve25519_sk: *mut libc::c_uchar,
        ed25519_sk: *const libc::c_uchar,
    ) -> libc::c_int;
}

use std::convert::AsMut;


fn pk_to_curve(pk: &[u8]) -> [u8; 32] {
    let mut result = [0; 32];
    unsafe {
        crypto_sign_ed25519_pk_to_curve25519(result.as_mut_ptr(), pk.as_ptr());
    }
    result
}

fn sk_to_curve(sk: &sign::ed25519::SecretKey) -> [u8; 32] {
    let mut result = [0; 32];
    unsafe {
        crypto_sign_ed25519_sk_to_curve25519(result.as_mut_ptr(), sk[..].as_ptr());
    }
    result
}

struct WriteBoxStream<T: AsyncWrite> {
    key: secretbox::Key,
    nonce: secretbox::Nonce,

    stream: T,    
}

trait NonceIncrementExt {
    fn increment_be_inplace(&mut self) -> ();
}

impl NonceIncrementExt for secretbox::Nonce {
    fn increment_be_inplace(self: &mut secretbox::Nonce) {
        let bytes = &mut self.0;

        let mut i: isize = (bytes.len() - 1) as isize;
        while i >= 0 && bytes[i as usize] == 0xff {
            bytes[i as usize] = 0;
            i -= 1;
        }
        if i <= 0 { return }
        bytes[i as usize] += 1;
    }
}

impl<T: AsyncWrite> AsyncWrite for WriteBoxStream<T> {
    fn poll_write(
        &mut self,
        lw: &LocalWaker,
        buf: &[u8]
    ) -> Poll<Result<usize, futures::io::Error>> {
        assert!(buf.len() < 4096);

        let nonce_one = self.nonce.clone();
        self.nonce.increment_be_inplace();
        let nonce_two = self.nonce.clone();
        self.nonce.increment_be_inplace();

        let b = secretbox::seal(buf, &nonce_two, &self.key);
        let (tag, encrypted_b) = b.split_at(16);

        let mut header = Vec::new();
        header.write_u16::<BigEndian>(buf.len() as u16).unwrap();
        header.extend_from_slice(&tag[..]);

        let h = secretbox::seal(&header[..], &nonce_one, &self.key);

        let mut message = Vec::new();
        message.extend_from_slice(&h[..]);
        message.extend_from_slice(encrypted_b);

        self.stream.poll_write(lw, &message[..])
    }

    fn poll_flush(&mut self, lw: &LocalWaker) -> Poll<Result<(), futures::io::Error>> {
        self.stream.poll_flush(lw)
    }

    fn poll_close(&mut self, lw: &LocalWaker) -> Poll<Result<(), futures::io::Error>> {
        self.stream.poll_close(lw)
    }
}

async fn read_box<T: AsyncRead>(b: &mut ReadBoxStream<T>) -> Vec<u8> {
    let mut header_enc = [0u8; 34];
    await!(b.stream.read_exact(&mut header_enc)).unwrap();
    let header = secretbox::open(&header_enc, &b.nonce, &b.key).unwrap();
    b.nonce.increment_be_inplace();
    let (len_buf, tag_buf) = header.split_at(2);
    let len = std::io::Cursor::new(&len_buf[..]).read_u16::<BigEndian>().unwrap() as usize;
    let tag = secretbox::Tag::from_slice(&tag_buf[..]).unwrap();
    println!("opened header: len = {:?}, tag = {:?}", len, tag);

    let mut data = Vec::with_capacity(len);
    data.resize(len, 0);
    await!(b.stream.read_exact(data.as_mut_slice())).unwrap();

    secretbox::open_detached(&mut data, &tag, &b.nonce, &b.key).unwrap();
    b.nonce.increment_be_inplace();

    data
}

struct ReadBoxStream<T> {
    key: secretbox::Key,
    nonce: secretbox::Nonce,

    stream: T,

    enc_offset: usize,

    // The first 34 bytes are the encrypted header, then the rest is the encrypted payload.
    enc_bytes: [u8; 16 + 2 + 16 + 4096],

    dec_offset: usize,
    dec_buf: Option<Vec<u8>>,
}

impl<T: AsyncRead> AsyncRead for ReadBoxStream<T> {
    fn poll_read(
        &mut self, 
        lw: &LocalWaker, 
        buf: &mut [u8]
    ) -> Poll<Result<usize, futures::io::Error>> {
        let mut pinned = read_box(self);
        let x = unsafe { std::pin::Pin::new_unchecked(&mut pinned) };
        x.poll(lw).map(|x| {
            assert!(x.len() <= buf.len());
            buf[..x.len()].copy_from_slice(&x[..]);
            Ok(x.len())
        })
        /*
        println!("poll_read buf {}", buf.len());
        // We previously decoded too many bytes for buf. Just return some of those bytes.
        if let Some(dec_buf) = &self.dec_buf {
            let to_copy = std::cmp::min(dec_buf.len() - self.dec_offset, buf.len());
            assert!(to_copy > 0);
            buf[..to_copy].copy_from_slice(&dec_buf[self.dec_offset..self.dec_offset + to_copy]);
            self.dec_offset += to_copy;
            if self.dec_offset == dec_buf.len() {
                self.dec_buf = None;
                self.dec_offset = 0;
            }
            println!("returning from dec_buf");
            return Poll::Ready(Ok(to_copy));
        }

        let bytes_read = match self.stream.poll_read(lw, &mut self.enc_bytes[self.enc_offset..]) {
            Poll::Ready(Ok(bytes_read)) => {
                bytes_read
            },
            // If we got an error or poll_read returned pending, do nothing.
            result => {
                println!("chain poll read failed {:?}", result);
                return result;
            }
        };

        self.enc_offset += bytes_read;
        println!("Read {} bytes from network. {} bytes pending", bytes_read, self.enc_offset);
        println!("Got bytes {:?}", &self.enc_bytes[34..self.enc_offset]);

        // We have a chunk from enc_bytes[0] to enc_offset to try and decode.

        // The header is exactly 34 bytes. If we have less than that, wait until we have more and try again.
        if self.enc_offset < 34 { return Poll::Pending; }
        println!("Have enough");

        let (header_enc, rest) = &self.enc_bytes.split_at(34);
        let header_dec = secretbox::open(&header_enc, &self.nonce, &self.key).unwrap();

        let len = std::io::Cursor::new(&header_dec).read_u16::<BigEndian>().unwrap() as usize;
        // let len = ((header_dec[0] as usize) << 8) | (header_dec[1] as usize); // Big endian read.
        let body_auth_tag = &header_dec[2..];
        assert_eq!(body_auth_tag.len(), 16);

        println!("len {} bytes_read {} {:?} {:?} enc_offset {}", len, bytes_read, header_dec, self.nonce, self.enc_offset);

        // Uuuummm len is actually the decrypted length. No idea if this will 100% match.
        if self.enc_offset < 34 + len { return Poll::Pending; }

        self.nonce.increment_be_inplace();

        let mut data_enc = Vec::with_capacity(16 + len);
        data_enc.extend_from_slice(body_auth_tag);
        data_enc.extend_from_slice(&rest[..len]);

        // println!("data_enc {:?}", data_enc);

        // Hold off on saving the new nonce until decryption succeeds. (Not sure if this is needed...)
        // let result = secretbox::open_detached(&mut self.enc_bytes[34..34+len],
        //     &secretbox::Tag::from_slice(body_auth_tag).unwrap(),
        //     &nonce2, &self.key
        // );
        // result.unwrap();

        // self.nonce.increment_be_inplace();

        // println!("nonce {:?}", self.nonce);
        // println!("nonc2 {:?}", nonce2);

        // assert_eq!(data_enc.len(), 16 + len);

        //secretbox::open(data_enc.as_slice(), &nonce2, &self.key).unwrap();
        let data_dec = match secretbox::open(data_enc.as_slice(), &self.nonce, &self.key) {
            Err(()) => {
                println!("Data decryption failed... promise will still be pending?");
                return Poll::Pending;
            }
            Ok(data) => { data }
        };
        println!("Decryption succeeded: {:?}", data_dec);
        self.nonce.increment_be_inplace();

        let to_copy = std::cmp::min(len, buf.len());
        // Copy as many bytes as we can directly.
        buf[..to_copy].copy_from_slice(&data_dec[..to_copy]);
        if to_copy > buf.len() {
            self.dec_buf = Some(data_dec);
            self.dec_offset = to_copy;
        }

        //self.nonce = nonce2;

        return Poll::Ready(Ok(to_copy));
        */
    }

}

async fn handshake() -> io::Result<(WriteBoxStream<impl AsyncWrite>, ReadBoxStream<impl AsyncRead>)> {
    let discovery = "net:192.168.2.4:8008~shs:tPF29LyiYrobdLcAZnBIRNMjAZv38qa4OXnlbKb1zN8=";
    //let discovery = "net:192.168.1.20:8008~shs:ppR/uuTDeJzHZ29jYNPvSj3RZu9Z1hciaxzMAduRAbU=";
    let config = parse_multiserver_address(discovery);
    let (client_longterm_pk, client_longterm_sk) = sign::gen_keypair();
    let server_public_key = match config[0][1] {
        ConnPartConfig::SimpleHandshake { public_key } => { public_key }
        _ => panic!()
    };

    let mut stream = await!(TcpStream::connect(&"127.0.0.1:8008".parse().unwrap()))?;

    let (client_epk, esk) = box_::gen_keypair();

    let network_id: [u8; 32] = [0xd4, 0xa1, 0xcb, 0x88, 0xa6, 0x6f, 0x02, 0xf8, 0xdb, 0x63, 0x5c, 0xe2, 0x64, 0x41, 0xcc, 0x5d, 0xac, 0x1b, 0x08, 0x42, 0x0c, 0xea, 0xac, 0x23, 0x08, 0x39, 0xb7, 0x55, 0x84, 0x5a, 0x9f, 0xfb];
    let network_id_key = auth::Key::from_slice(&network_id).unwrap();

    // 1: Client hello
    let hmac_client_epk = auth::authenticate(&client_epk[..], &network_id_key);

    await!(stream.write_all(&hmac_client_epk[..]))?;
    await!(stream.write_all(&client_epk[..]))?;

    // 2: Server hello
    let mut server_hello = [0u8; 64];
    await!(stream.read_exact(&mut server_hello))?;

    let server_hmac = &server_hello[..32];
    let server_epk = &server_hello[32..];

    assert!(auth::verify(&auth::Tag::from_slice(&server_hmac).unwrap(), &server_epk, &network_id_key));

    let shared_secret_ab = scalarmult(
        &Scalar::from_slice(&esk[..]).unwrap(),
        &GroupElement::from_slice(&server_epk).unwrap()
    ).unwrap();

    let server_longterm_curve = pk_to_curve(&server_public_key[..]);
    let shared_secret_aB = scalarmult(
        &Scalar::from_slice(&esk[..]).unwrap(),
        &GroupElement::from_slice(&server_longterm_curve[..]).unwrap()
    ).unwrap();

    // 3: Client authenticate
    let digest = sha256::hash(&shared_secret_ab[..]);

    let mut mesg = Vec::new();
    mesg.extend_from_slice(&network_id);
    mesg.extend_from_slice(&server_public_key[..]);
    mesg.extend_from_slice(&digest[..]);

    let detached_signature_A = sign::sign_detached(&mesg, &client_longterm_sk);

    let mut s = sha256::State::new();
    s.update(&network_id);
    s.update(&shared_secret_ab[..]);
    s.update(&shared_secret_aB[..]);
    let some_key = s.finalize();
    let k = secretbox::Key::from_slice(&some_key[..]).unwrap();
    let mut mesg2 = Vec::new();
    mesg2.extend_from_slice(&detached_signature_A[..]);
    mesg2.extend_from_slice(&client_longterm_pk[..]);
    let b = secretbox::seal(&mesg2, &secretbox::Nonce::from_slice(&[0u8; 24]).unwrap(), &k);

    await!(stream.write_all(&b))?;

    let shared_secret_Ab = scalarmult(
        &Scalar::from_slice(&sk_to_curve(&client_longterm_sk)).unwrap(),
        &GroupElement::from_slice(&server_epk[..]).unwrap()
    ).unwrap();

    // 4. Server accept

    let mut server_accept = [0u8; 80];
    await!(stream.read_exact(&mut server_accept))?;

    let mut s = sha256::State::new();
    s.update(&network_id);
    s.update(&shared_secret_ab[..]);
    s.update(&shared_secret_aB[..]);
    s.update(&shared_secret_Ab[..]);
    let digest2 = s.finalize();
    let k2 = secretbox::Key::from_slice(&digest2[..]).unwrap();
    let nonce = secretbox::Nonce::from_slice(&[0u8; 24]).unwrap();
    let detached_signature_B = secretbox::open(
        &server_accept,
        &nonce,
        &k2
    ).unwrap();

    let mut mesg2 = Vec::new();
    mesg2.extend_from_slice(&network_id);
    mesg2.extend_from_slice(&detached_signature_A[..]);
    mesg2.extend_from_slice(&client_longterm_pk[..]);
    mesg2.extend_from_slice(&sha256::hash(&shared_secret_ab[..])[..]);
    assert!(sign::verify_detached(&sign::Signature::from_slice(&detached_signature_B[..]).unwrap(), &mesg2, &server_public_key));

    println!("Handshake completed.");

    let digest3 = sha256::hash(&digest2[..]);
    let cs_box_key = {
        let mut s = sha256::State::new();
        s.update(&digest3[..]);
        s.update(&server_public_key[..]);
        s.finalize()
    };
    let sc_box_key = {
        let mut s = sha256::State::new();
        s.update(&digest3[..]);
        s.update(&client_longterm_pk[..]);
        s.finalize()
    };

    let hmac_server_epk = auth::authenticate(&server_epk[..], &network_id_key);

    let (read_half, write_half) = stream.split();

    let cs_bs = WriteBoxStream {
        key: secretbox::Key::from_slice(&cs_box_key[..]).unwrap(),
        nonce: secretbox::Nonce::from_slice(&hmac_server_epk[..24]).unwrap(),
        stream: write_half
    };
    let sc_bs = ReadBoxStream {
        key: secretbox::Key::from_slice(&sc_box_key[..]).unwrap(),
        nonce: secretbox::Nonce::from_slice(&hmac_client_epk[..24]).unwrap(),
        stream: read_half,
        enc_offset: 0,
        enc_bytes: [0u8; 16 + 2 + 16 + 4096],
        dec_offset: 0,
        dec_buf: None,
    };

    Ok((cs_bs, sc_bs))
}

fn main() -> () {
    executor::block_on(async {
        let (writer, mut reader) = await!(handshake()).unwrap();
        loop {
            let mut buf = [0; 4096];
            let msg = await!(reader.read(&mut buf)).unwrap();
            println!("got {} bytes: {:?}", msg, buf.split_at(msg).0);
        }
    })
}

// e.g. net:192.168.2.4:8008~shs:tPF29LyiYrobdLcAZnBIRNMjAZv38qa4OXnlbKb1zN8=
fn parse_multiserver_address(msg: &str) -> Vec<Vec<ConnPartConfig>> {
    msg.split(";").map(|addr| {
        addr.split("~").map(|part| {
            let mut ps = part.splitn(2, ":");
            let proto = ps.next().expect("proto");
            let desc = ps.next().expect("desc");

            match proto {
                "net" => {
                    ConnPartConfig::NetTcp {
                        address: SocketAddr::from_str(desc).unwrap()
                    }
                }
                "shs" => {
                    let pk = base64::decode(&desc).unwrap();
                    ConnPartConfig::SimpleHandshake {
                        public_key: PublicKey::from_slice(&pk).unwrap()
                    }
                }
                _ => panic!("uhh?")
            }
        }).collect::<Vec<_>>()
    }).collect::<Vec<_>>()
}

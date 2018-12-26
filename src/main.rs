#![feature(async_await, await_macro, futures_api)]

#[macro_use]
extern crate serde_json;

use sodiumoxide::crypto::{box_, sign, auth, scalarmult, secretbox};
use sodiumoxide::crypto::hash::sha256;
use sodiumoxide::crypto::scalarmult::*;
use sodiumoxide::crypto::sign::{PublicKey, SecretKey};
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

use net2::UdpBuilder;
use net2::unix::UnixUdpBuilderExt;

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

struct BoxStream<T> {
    key: secretbox::Key,
    nonce: secretbox::Nonce,

    stream: T,    
}

// struct ReadBoxStream<T: AsyncRead> {
//     key: secretbox::Key,
//     nonce: secretbox::Nonce,

//     stream: T,
// }

impl<T: AsyncWrite> AsyncWrite for BoxStream<T> {
    fn poll_write(
        &mut self,
        lw: &LocalWaker,
        buf: &[u8]
    ) -> Poll<Result<usize, futures::io::Error>> {
        assert!(buf.len() < 4096);

        let nonce_one = self.nonce.clone();
        self.nonce.increment_le_inplace();
        let nonce_two = self.nonce.clone();
        self.nonce.increment_le_inplace();

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

async fn read_box<T: AsyncRead>(b: &mut BoxStream<T>) {
    loop {
        let mut header = [0u8; 34];
        await!(b.stream.read_exact(&mut header)).unwrap();
        
        secretbox::open(&header, &b.nonce, &b.key).unwrap();
        b.nonce.increment_le_inplace();

        let len = std::io::Cursor::new(&header[..]).read_u16::<BigEndian>().unwrap() as usize;

        let mut data = Vec::with_capacity(len);
        data.resize(len, 0);
        await!(b.stream.read_exact(data.as_mut_slice())).unwrap();

        unimplemented!()
    }
}

impl<T: AsyncRead> AsyncRead for BoxStream<T> {
    fn poll_read(
        &mut self, 
        lw: &LocalWaker, 
        buf: &mut [u8]
    ) -> Poll<Result<usize, futures::io::Error>> {
        
        //let mut local_buf = [0u8; 4096];
        //self.stream.poll_read(lw, local_buf)
        unimplemented!()
    }

}

async fn foo() -> io::Result<()> {
    let discovery = "net:192.168.2.4:8008~shs:tPF29LyiYrobdLcAZnBIRNMjAZv38qa4OXnlbKb1zN8=";
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

    let cs_bs = BoxStream {
        key: secretbox::Key::from_slice(&cs_box_key[..]).unwrap(),
        nonce: secretbox::Nonce::from_slice(&hmac_server_epk[..24]).unwrap(),
        stream: unimplemented!()
    };
    let sc_bs = BoxStream {
        key: secretbox::Key::from_slice(&sc_box_key[..]).unwrap(),
        nonce: secretbox::Nonce::from_slice(&hmac_client_epk[..24]).unwrap(),
        stream: unimplemented!()
    };

    Ok(())
}

fn main() -> () {
    executor::block_on(async {
        await!(foo());
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

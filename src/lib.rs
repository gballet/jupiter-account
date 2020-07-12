extern crate secp256k1;
extern crate sha3;

use multiproof_rs::{ByteKey, Multiproof, NibbleKey};
use secp256k1::{
    recover as secp256k1_recover, sign as secp256k1_sign, verify as secp256k1_verify, Message,
    RecoveryId, SecretKey, Signature,
};
use sha3::{Digest, Keccak256};

#[derive(Debug, PartialEq)]
pub enum Account {
    // Address, nonce, value, code, state
    Existing(NibbleKey, u64, u64, Vec<u8>, Vec<u8>),
    Empty,
}

impl Account {
    pub fn balance(&self) -> u64 {
        match self {
            Self::Existing(_, _, balance, _, _) => *balance,
            _ => 0u64,
        }
    }

    pub fn balance_mut(&mut self) -> Option<&mut u64> {
        match self {
            Self::Existing(_, _, ref mut balance, _, _) => Some(balance),
            _ => None,
        }
    }

    pub fn nonce(&self) -> u64 {
        match self {
            Self::Existing(_, nonce, _, _, _) => *nonce,
            _ => 0u64,
        }
    }

    pub fn nonce_mut(&mut self) -> Option<&mut u64> {
        match self {
            Self::Existing(_, ref mut nonce, _, _, _) => Some(nonce),
            _ => None,
        }
    }
}

impl Account {
    pub fn deposit(&mut self, amount: u64) -> Result<(), &str> {
        match self {
            Account::Existing(_, _, ref mut balance, _, _) => *balance += amount,
            _ => return Err("can not increase the balance of an empty account"),
        }
        Ok(())
    }

    pub fn withdraw(&mut self, amount: u64) -> Result<(), &str> {
        match self {
            Account::Existing(_, _, ref mut balance, _, _) => {
                if *balance >= amount {
                    *balance += amount
                } else {
                    return Err("Insufficient balance");
                }
            }
            _ => return Err("Can not increase the balance of an empty account"),
        }
        Ok(())
    }
}

impl From<SecretKey> for Account {
    fn from(sk: SecretKey) -> Self {
        let msg = Message::parse_slice(&[0x55u8; 32]).unwrap();
        let (user1_sig, user1_recid) = secp256k1_sign(&msg, &sk);
        let user1_pkey = secp256k1_recover(&msg, &user1_sig, &user1_recid).unwrap();
        let mut keccak256 = Keccak256::new();
        keccak256.input(&user1_pkey.serialize()[..]);
        let addr1 = keccak256.result_reset()[..20].to_vec();
        let user1_addr = NibbleKey::from(ByteKey::from(addr1));
        Account::Existing(user1_addr, 0, 0, vec![], vec![])
    }
}

impl rlp::Decodable for Account {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        match rlp.item_count()? {
            5 => {
                // TODO update multiproof to implement Into<Vec<u8>> for ByteKey so
                // that keys can be stored as bytes instead of nibbles, which would
                // make proofs shorter.
                let addr = NibbleKey::from(rlp.val_at::<Vec<u8>>(0)?);
                let nonce = rlp.val_at(1)?;
                let balance = rlp.val_at(2)?;
                let code = rlp.val_at(3)?;
                let state = rlp.val_at(4)?;

                Ok(Account::Existing(addr, nonce, balance, code, state))
            }
            0 => Ok(Account::Empty),
            n => panic!(format!("Invalid payload, item count={}", n)),
        }
    }
}

impl rlp::Encodable for Account {
    fn rlp_append(&self, stream: &mut rlp::RlpStream) {
        match self {
            Account::Empty => {
                stream.append_empty_data();
            }
            Account::Existing(addr, nonce, balance, code, state) => {
                stream
                    .begin_unbounded_list()
                    .append(addr)
                    .append(nonce)
                    .append(balance)
                    .append(code)
                    .append(state)
                    .finalize_unbounded_list();
            }
        };
    }
}

/// Represents a layer-2 transaction.
#[derive(Debug)]
pub struct Tx {
    pub from: NibbleKey,
    pub to: NibbleKey,
    pub nonce: u64,
    pub value: u64,
    pub call: u32, // Txs have only one instruction in this model, and it's a "call"
    pub data: Vec<u8>,
    pub signature: Vec<u8>,
}

impl rlp::Encodable for Tx {
    fn rlp_append(&self, stream: &mut rlp::RlpStream) {
        stream
            .begin_unbounded_list()
            .append(&self.from)
            .append(&self.to)
            .append(&self.nonce)
            .append(&self.value)
            .append(&self.call)
            .append(&self.data)
            .append(&self.signature)
            .finalize_unbounded_list();
    }
}

impl rlp::Decodable for Tx {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        Ok(Tx {
            from: NibbleKey::from(rlp.val_at::<Vec<u8>>(0)?),
            to: NibbleKey::from(rlp.val_at::<Vec<u8>>(1)?),
            nonce: rlp.val_at(2)?,
            value: rlp.val_at(3)?,
            call: rlp.val_at(4)?,
            data: rlp.val_at(5)?,
            signature: rlp.val_at(6)?,
        })
    }
}

impl Tx {
    pub fn new(from: Vec<u8>, to: Vec<u8>, nonce: u64) -> Self {
        Tx {
            from: NibbleKey::from(ByteKey::from(from)),
            to: NibbleKey::from(ByteKey::from(to)),
            nonce: nonce,
            signature: vec![0u8; 65],
            call: 0,
            value: 0,
            data: vec![],
        }
    }
    pub fn sign(&mut self, skey: &[u8; 32]) {
        let skey = SecretKey::parse(skey).unwrap();
        let mut keccak256 = Keccak256::new();
        keccak256.input(rlp::encode(&self.from));
        keccak256.input(rlp::encode(&self.to));
        keccak256.input(rlp::encode(&self.nonce));
        keccak256.input(rlp::encode(&self.value));
        keccak256.input(rlp::encode(&self.call));
        keccak256.input(rlp::encode(&self.data));
        let message_data = keccak256.result();
        let message = Message::parse_slice(&message_data).unwrap();
        let (sig, recid) = secp256k1_sign(&message, &skey);
        self.signature[..64].copy_from_slice(&sig.serialize()[..]);
        self.signature[64] = recid.serialize();
    }

    pub fn sig_check(&self) -> (bool, NibbleKey) {
        // Recover the signature from the tx data.
        let mut keccak256 = Keccak256::new();
        keccak256.input(rlp::encode(&self.from));
        keccak256.input(rlp::encode(&self.to));
        keccak256.input(rlp::encode(&self.nonce));
        keccak256.input(rlp::encode(&self.value));
        keccak256.input(rlp::encode(&self.call));
        keccak256.input(rlp::encode(&self.data));
        let message_data = keccak256.result_reset();
        let message = Message::parse_slice(&message_data).unwrap();
        let signature = Signature::parse_slice(&self.signature[..64]).unwrap();
        let recover = RecoveryId::parse(self.signature[64]).unwrap();
        let pkey = secp256k1_recover(&message, &signature, &recover).unwrap();

        // Verify the signature
        if !secp256k1_verify(&message, &signature, &pkey) {
            return (false, NibbleKey::from(vec![]));
        }

        // Get the address
        keccak256.input(&pkey.serialize()[..]);
        let addr = keccak256.result()[..20].to_vec();
        let addr = NibbleKey::from(ByteKey::from(addr));

        return (addr.clone() == self.from, addr);
    }
}

/// Represents the data that should be encoded inside a layer one `data` field.
#[derive(Debug)]
pub struct TxData {
    pub proof: Multiproof,
    pub txs: Vec<Tx>,
}

impl rlp::Encodable for TxData {
    fn rlp_append(&self, stream: &mut rlp::RlpStream) {
        stream
            .begin_unbounded_list()
            .append(&self.proof)
            .append_list(&self.txs)
            .finalize_unbounded_list();
    }
}

impl rlp::Decodable for TxData {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        Ok(TxData {
            proof: rlp.val_at::<Multiproof>(0)?,
            txs: rlp.list_at(1)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign() {
        let skey = [1u8; 32];
        let mut tx = Tx::new(
            vec![
                181, 154, 35, 232, 170, 166, 228, 13, 59, 214, 229, 236, 205, 9, 152, 122, 184, 20,
                30, 197,
            ],
            vec![6u8; 20],
            1,
        );

        tx.sign(&skey);

        let (valid, _addr) = tx.sig_check();
        assert!(valid);
    }
}

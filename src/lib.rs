use multiproof_rs::{Multiproof, NibbleKey};

#[derive(Debug, PartialEq)]
pub enum Account {
    // Address, nonce, value, code, state
    Existing(NibbleKey, u64, u64, Vec<u8>, bool),
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
        })
    }
}

/// Represents the data that should be encoded inside a layer one `data` field.
#[derive(Debug)]
pub struct TxData {
    pub proof: Multiproof,
    pub txs: Vec<Tx>,
    pub signature: Vec<u8>,
}

impl rlp::Encodable for TxData {
    fn rlp_append(&self, stream: &mut rlp::RlpStream) {
        stream
            .begin_unbounded_list()
            .append(&self.proof)
            .append_list(&self.txs)
            .append(&self.signature)
            .finalize_unbounded_list();
    }
}

impl rlp::Decodable for TxData {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        Ok(TxData {
            proof: rlp.val_at::<Multiproof>(0)?,
            txs: rlp.list_at(1)?,
            signature: rlp.val_at::<Vec<u8>>(2)?,
        })
    }
}

use bdk::bitcoin::secp256k1::Secp256k1;
use bdk::bitcoin::util::bip32::{DerivationPath, KeySource};
use bdk::bitcoin::Amount;
use bdk::bitcoin::Network;
use bdk::bitcoincore_rpc::{Auth as rpc_auth, Client, RpcApi};

use bdk::blockchain::rpc::{Auth, RpcBlockchain, RpcConfig};
use bdk::blockchain::{ConfigurableBlockchain, NoopProgress};

use bdk::keys::bip39::{Language, Mnemonic, WordCount};
use bdk::keys::DescriptorKey::Secret;
use bdk::keys::{DerivableKey, DescriptorKey, ExtendedKey, GeneratableKey, GeneratedKey};

use bdk::miniscript::miniscript::Segwitv0;

use bdk::wallet::{signer::SignOptions, wallet_name_from_descriptor, AddressIndex};
use bdk::Wallet;

use bdk::sled;

use std::str::FromStr;

fn main() {
    // Create a RPC interface
    let rpc_auth = rpc_auth::UserPass("admin".to_string(), "passw".to_string());
    let core_rpc = Client::new("http://127.0.0.1:18443/wallet/test", rpc_auth).unwrap();

    // Create the test wallet
    let _ = core_rpc.create_wallet("test", None, None, None, None);

    // Get a new address
    let core_address = core_rpc.get_new_address(None, None).unwrap();

    // Generate 101 blocks and use the above address as coinbase
    core_rpc.generate_to_address(101, &core_address).unwrap();

    // Get receive and change descriptor
    let (receive_desc, change_desc) = get_descriptors();

    // Use deterministic wallet name derived from descriptor
    let wallet_name = wallet_name_from_descriptor(
        &receive_desc,
        Some(&change_desc),
        Network::Regtest,
        &Secp256k1::new(),
    )
    .unwrap();

    // Create the datadir to store wallet data
    let mut datadir = dirs_next::home_dir().unwrap();
    datadir.push(".bdk-example");
    let database = sled::open(datadir).unwrap();
    let db_tree = database.open_tree(wallet_name.clone()).unwrap();

    // Set RPC username and password
    let auth = Auth::UserPass {
        username: "admin".to_string(),
        password: "passw".to_string(),
    };

    // Set RPC url
    let mut rpc_url = "http://".to_string();
    rpc_url.push_str("127.0.0.1:18443");

    // Setup the RPC configuration
    let rpc_config = RpcConfig {
        url: rpc_url,
        auth,
        network: Network::Regtest,
        wallet_name,
        skip_blocks: None,
    };

    // Use the above configuration to create a RPC blockchain backend
    let blockchain = RpcBlockchain::from_config(&rpc_config).unwrap();

    // Combine everything and finally create the BDK wallet structure
    let wallet = Wallet::new(
        &receive_desc,
        Some(&change_desc),
        Network::Regtest,
        db_tree,
        blockchain,
    )
    .unwrap();

    // Sync the wallet
    wallet.sync(NoopProgress, None).unwrap();

    // Fetch a fresh address to receive coins
    let address = wallet.get_address(AddressIndex::New).unwrap().address;

    // Send 10 BTC from Core to BDK
    core_rpc
        .send_to_address(
            &address,
            Amount::from_btc(10.0).unwrap(),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

    // Confirm transaction by generating some blocks
    core_rpc.generate_to_address(1, &core_address).unwrap();

    // Sync the BDK wallet
    wallet.sync(NoopProgress, None).unwrap();

    // Create a transaction builder
    let mut tx_builder = wallet.build_tx();

    // Set recipient of the transaction
    tx_builder.set_recipients(vec![(core_address.script_pubkey(), 500000000)]);

    // Finalise the transaction and extract PSBT
    let (mut psbt, _) = tx_builder.finish().unwrap();

    // Set signing option
    let signopt = SignOptions {
        assume_height: None,
        ..Default::default()
    };

    // Sign the above psbt with signing option
    wallet.sign(&mut psbt, signopt).unwrap();

    // Extract the final transaction
    let tx = psbt.extract_tx();

    // Broadcast the transaction
    wallet.broadcast(&tx).unwrap();

    // Confirm transaction by generating some blocks
    core_rpc.generate_to_address(1, &core_address).unwrap();

    // Sync the BDK wallet
    wallet.sync(NoopProgress, None).unwrap();

    // Fetch and display wallet balances
    let core_balance = core_rpc.get_balance(None, None).unwrap();
    let bdk_balance = Amount::from_sat(wallet.get_balance().unwrap());
    println!("core wallet balance: {:#?}", core_balance);
    println!("BDK wallet balance: {:#?}", bdk_balance);
}

// generate fresh descriptor strings and return them via (receive, change) tupple
fn get_descriptors() -> (String, String) {
    // Create a new secp context
    let secp = Secp256k1::new();

    // You can also set a password to unlock the mnemonic
    let password = Some("random password".to_string());

    // Generate a fresh menmonic, and from their, a fresh private key xprv
    let mnemonic: GeneratedKey<_, Segwitv0> =
        Mnemonic::generate((WordCount::Words12, Language::English)).unwrap();
    let mnemonic = mnemonic.into_key();
    let xkey: ExtendedKey = (mnemonic, password).into_extended_key().unwrap();
    let xprv = xkey.into_xprv(Network::Regtest).unwrap();

    // Derive our descriptors to use
    // We use the following paths for recieve and change descriptor
    // receive: "m/84h/1h/0h/0"
    // change: "m/84h/1h/0h/1"
    let mut keys = Vec::new();

    for path in ["m/84h/1h/0h/0", "m/84h/1h/0h/1"].iter() {
        let deriv_path: DerivationPath = DerivationPath::from_str(path).unwrap();
        let derived_xprv = &xprv.derive_priv(&secp, &deriv_path).unwrap();
        let origin: KeySource = (xprv.fingerprint(&secp), deriv_path);
        let derived_xprv_desc_key: DescriptorKey<Segwitv0> = derived_xprv
            .into_descriptor_key(Some(origin), DerivationPath::default())
            .unwrap();

        // Wrap the derived key with the wpkh() string to produce a descriptor string
        if let Secret(key, _, _) = derived_xprv_desc_key {
            let mut desc = "wpkh(".to_string();
            desc.push_str(&key.to_string());
            desc.push_str(")");
            keys.push(desc);
        }
    }

    // Return the keys as a tupple
    (keys[0].clone(), keys[1].clone())
}

#[cfg(test)]
mod test {
    use super::*;
    use bdk::bitcoin::consensus::encode::deserialize;
    use bdk::bitcoin::Transaction;
    use bdk::bitcoincore_rpc::json::CreateRawTransactionInput;
    use bdk::wallet::verify::verify_tx;
    use std::collections::HashMap;

    #[test]
    fn test_transaction_validation() {
        // Create a RPC interface
        let rpc_auth = rpc_auth::UserPass("admin".to_string(), "passw".to_string());
        let core_rpc =
            Client::new("http://127.0.0.1:18443/wallet/test-verification", rpc_auth).unwrap();

        // Create the test wallet
        core_rpc
            .create_wallet("test-verification", None, None, None, None)
            .unwrap();

        // Get a new address
        let core_coinbase_addr = core_rpc.get_new_address(None, None).unwrap();

        // Generate 101 blocks and use the above address as coinbase
        core_rpc
            .generate_to_address(101, &core_coinbase_addr)
            .unwrap();

        // -----------
        // Create BDK wallet
        // Get receive and change descriptor
        let (receive_desc, change_desc) = get_descriptors();

        // Use deterministic wallet name derived from descriptor
        let wallet_name = wallet_name_from_descriptor(
            &receive_desc,
            Some(&change_desc),
            Network::Regtest,
            &Secp256k1::new(),
        )
        .unwrap();

        // Create the datadir to store wallet data
        let mut datadir = dirs_next::home_dir().unwrap();
        datadir.push(".bdk-example");
        let database = sled::open(datadir).unwrap();
        let db_tree = database.open_tree(wallet_name.clone()).unwrap();

        // Set RPC username and password
        let auth = Auth::UserPass {
            username: "admin".to_string(),
            password: "passw".to_string(),
        };

        // Set RPC url
        let mut rpc_url = "http://".to_string();
        rpc_url.push_str("127.0.0.1:18443");

        // Setup the RPC configuration
        let rpc_config = RpcConfig {
            url: rpc_url,
            auth,
            network: Network::Regtest,
            wallet_name,
            skip_blocks: None,
        };

        // Use the above configuration to create a RPC blockchain backend
        let blockchain = RpcBlockchain::from_config(&rpc_config).unwrap();

        // Combine everything and finally create the BDK wallet structure
        let wallet = Wallet::new(
            &receive_desc,
            Some(&change_desc),
            Network::Regtest,
            db_tree,
            blockchain,
        )
        .unwrap();

        // Sync the wallet
        wallet.sync(NoopProgress, None).unwrap();

        // Start test setup
        // tx1 = Coinbase -> core_reg_addr
        // tx2 = tx1 -> ((bdk_addr, 4.0), (core_change_addr, 0.999))
        // tx2 is a in wallet transaction, while tx1 is not
        // trying to verify tx1 with RPCBlockchain will fail

        // Get a regular core address
        let core_reg_addr = core_rpc.get_new_address(None, None).unwrap();

        // Send 5 btc to core regular address, no change
        let tx1_id = core_rpc
            .send_to_address(
                &core_reg_addr,
                Amount::from_btc(5.0).unwrap(),
                None,
                None,
                Some(true),
                None,
                None,
                None,
            )
            .unwrap();

        // confirm tx1
        core_rpc
            .generate_to_address(1, &core_coinbase_addr)
            .unwrap();

        // Get the tx1 transaction data
        let tx1 = core_rpc.get_transaction(&tx1_id, None).unwrap();
        let tx1 = deserialize::<Transaction>(&tx1.hex).unwrap();

        let bdk_addr = wallet.get_address(AddressIndex::New).unwrap();
        let core_change_addrs = core_rpc.get_new_address(None, None).unwrap();

        let mut output = HashMap::new();
        output.insert(bdk_addr.to_string(), Amount::from_btc(4.0).unwrap());
        output.insert(
            core_change_addrs.to_string(),
            Amount::from_btc(0.999).unwrap(),
        );
        let utxo = CreateRawTransactionInput {
            txid: tx1_id,
            vout: 0,
            sequence: None,
        };

        let raw_tx_2 = core_rpc
            .create_raw_transaction(&[utxo], &output, None, None)
            .unwrap();
        let signed_raw_tx_2 = core_rpc
            .sign_raw_transaction_with_wallet(&raw_tx_2, None, None)
            .unwrap();
        let signed_tx_2 = deserialize::<Transaction>(&signed_raw_tx_2.hex).unwrap();

        core_rpc.send_raw_transaction(&signed_tx_2).unwrap();
        wallet.sync(NoopProgress, None).unwrap();

        // This will fail
        verify_tx(&tx1, &*wallet.database(), wallet.client()).unwrap();
    }
}

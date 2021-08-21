use bdk::bitcoin::Network;
use bdk::bitcoin::secp256k1::Secp256k1;
use bdk::bitcoin::util::bip32::{DerivationPath, KeySource};
use bdk::bitcoin::Amount;
use bdk::bitcoincore_rpc::{Auth as rpc_auth, Client, RpcApi};

use bdk::blockchain::rpc::{Auth, RpcBlockchain, RpcConfig, wallet_name_from_descriptor};
use bdk::blockchain::{ConfigurableBlockchain, NoopProgress};

use bdk::keys::bip39::{Mnemonic, Language, MnemonicType};
use bdk::keys::{GeneratedKey, GeneratableKey, ExtendedKey, DerivableKey, DescriptorKey};
use bdk::keys::DescriptorKey::Secret;

use bdk::miniscript::miniscript::Segwitv0;

use bdk::Wallet;
use bdk::wallet::{AddressIndex, signer::SignOptions};

use bdk::sled;

use std::str::FromStr;

fn main() {
    // Create a RPC interface
    let rpc_auth = rpc_auth::UserPass(
        "admin".to_string(),
        "password".to_string()
    ); 
    let core_rpc = Client::new("http://127.0.0.1:18443/wallet/test".to_string(), rpc_auth).unwrap();

    // Create the test wallet 
    core_rpc.create_wallet("test", None, None, None, None).unwrap();
    
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
        &Secp256k1::new()
    ).unwrap();

    // Create the datadir to store wallet data
    let mut datadir = dirs_next::home_dir().unwrap();
    datadir.push(".bdk-example");
    let database = sled::open(datadir).unwrap();
    let db_tree = database.open_tree(wallet_name.clone()).unwrap();

    // Set RPC username and password
    let auth = Auth::UserPass {
        username: "admin".to_string(),
        password: "password".to_string()
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
    let wallet = Wallet::new(&receive_desc, Some(&change_desc), Network::Regtest, db_tree, blockchain).unwrap();

    // Sync the wallet
    wallet.sync(NoopProgress, None).unwrap();

    // Fetch a fresh address to receive coins
    let address = wallet.get_address(AddressIndex::New).unwrap().address;

    // Send 10 BTC from Core to BDK
    core_rpc.send_to_address(&address, Amount::from_btc(10.0).unwrap(), None, None, None, None, None, None).unwrap();

    // Confirm transaction by generating some blocks
    core_rpc.generate_to_address(1, &core_address).unwrap();

    // Sync the BDK wallet
    wallet.sync(NoopProgress, None).unwrap();

    // Create a transaction builder
    let mut tx_builder = wallet.build_tx();

    // Set recipient of the transaction
    tx_builder.set_recipients(vec!((core_address.script_pubkey(), 500000000)));

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
    wallet.broadcast(tx).unwrap();

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
                Mnemonic::generate((MnemonicType::Words12, Language::English)).unwrap();
    let mnemonic = mnemonic.into_key();
    let xkey: ExtendedKey = (mnemonic, password).into_extended_key().unwrap();
    let xprv = xkey.into_xprv(Network::Regtest).unwrap();

    // Derive our dewscriptors to use
    // We use the following paths for recieve and change descriptor
    // recieve: "m/84h/1h/0h/0"
    // change: "m/84h/1h/0h/1" 
    let mut keys = Vec::new();

    for path in ["m/84h/1h/0h/0", "m/84h/1h/0h/1"] {
        let deriv_path: DerivationPath = DerivationPath::from_str(path).unwrap();
        let derived_xprv = &xprv.derive_priv(&secp, &deriv_path).unwrap();
        let origin: KeySource = (xprv.fingerprint(&secp), deriv_path);
        let derived_xprv_desc_key: DescriptorKey<Segwitv0> =
        derived_xprv.into_descriptor_key(Some(origin), DerivationPath::default()).unwrap();

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

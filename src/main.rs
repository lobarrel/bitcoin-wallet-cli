use std::io;
use std::env;
use tui::{
    backend::{Backend, CrosstermBackend},
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::Span,
    widgets::{Block, BorderType, Borders, List, ListItem, ListState},
    Frame, Terminal
};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};

use bdk::{bitcoin::{Network, util::psbt::raw::Key}, sled::Tree, blockchain};
use bdk::bitcoin::secp256k1::Secp256k1;
use bdk::bitcoin::util::bip32::{DerivationPath, KeySource};
use bdk::bitcoin::Amount;
use bdk::bitcoin::Address;
//use bdk::bitcoincore_rpc::{Auth as rpc_auth, Client, RpcApi};

use bdk::blockchain::rpc::{Auth, RpcBlockchain, RpcConfig, wallet_name_from_descriptor};
use bdk::blockchain::{ElectrumBlockchain, ConfigurableBlockchain, NoopProgress};
use bdk::electrum_client::Client;

use bdk::keys::bip39::{Mnemonic, Language, MnemonicType};
use bdk::keys::{GeneratedKey, GeneratableKey, ExtendedKey, DerivableKey, DescriptorKey};
use bdk::keys::DescriptorKey::Secret;

use bdk::miniscript::miniscript::Segwitv0;

use bdk::Wallet;
use bdk::wallet::{AddressIndex, signer::SignOptions};

use bdk::sled;

use std::str::FromStr;



fn main(){

    //Create a terminal
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).unwrap();
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).unwrap();

    //terminal.draw(ui)

    if let Event::Key(key) = event::read().unwrap(){
        if let KeyCode::Char('n') = key.code {
            let wallet = new_wallet(); 
            println!("Wallet successfully created!");

            loop {
                if let Event::Key(key) = event::read().unwrap(){
                    if let KeyCode::Char('s') = key.code {
                        wallet.sync(NoopProgress, None).unwrap();
                        println!("Your wallet is synchronized!");
                    }
                    if let KeyCode::Char('a') = key.code {
                        let address = wallet.get_address(AddressIndex::New).unwrap().address;
                        println!("Address: {}", address);
                    }
                    if let KeyCode::Char('b') = key.code {
                        wallet.sync(NoopProgress, None).unwrap();
                        let balance = Amount::from_sat(wallet.get_balance().unwrap());
                        println!("Balance: {}", balance);
                    }
                    if let KeyCode::Char('t') = key.code {
                        println!("Recipient address: ");
                        let mut arg1 = String::new();
                        io::stdin().read_line(&mut arg1).unwrap();
                        let recipient_address = Address::from_str(&arg1.trim()).unwrap();
                        println!("Amount (sats): ");
                        let mut arg2 = String::new();
                        io::stdin().read_line(&mut arg2).unwrap();
                        let amount = arg2.trim().parse::<u64>().unwrap();

                        wallet.sync(NoopProgress, None).unwrap();
                        let mut tx_builder = wallet.build_tx();
                        tx_builder.set_recipients(vec!((recipient_address.script_pubkey(), amount)));

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
                        let txid = tx.txid();

                        // Broadcast the transaction
                        wallet.broadcast(tx).unwrap();
                        println!("Transaction completed successfully!\nTransaction ID: {}", txid);
                    }
                    if let KeyCode::Char('q') = key.code {
                        return;
                    }
                }
                
            }
        }
    }
    

    // restore terminal
    execute!(terminal.backend_mut(),LeaveAlternateScreen).unwrap();
    terminal.show_cursor().unwrap();

     
}


fn new_wallet() -> Wallet<ElectrumBlockchain, Tree>{

    //Electrum client
    let client = Client::new("ssl://electrum.blockstream.info:60002").unwrap();
    let blockchain = ElectrumBlockchain::from(client);

    //Get descriptors
    let (receive_desc, change_desc) = get_descriptors();
    // Use deterministic wallet name derived from descriptor
    let wallet_name = wallet_name_from_descriptor(
        &receive_desc,
        Some(&change_desc),
        Network::Testnet,
        &Secp256k1::new()
    ).unwrap();

    //Create datadir
    let mut datadir = dirs_next::home_dir().unwrap();
    datadir.push(".bdk-example");
    let database = sled::open(datadir).unwrap();
    let db_tree = database.open_tree(wallet_name.clone()).unwrap();

    //Create the wallet
    let wallet = Wallet::new(&receive_desc, Some(&change_desc), Network::Testnet, db_tree, blockchain).unwrap();
    return wallet;
}




////GENERATE DESCRIPTORS
fn get_descriptors() -> (String, String) {
    // Create a new secp context
    let secp = Secp256k1::new();
     
    // You can also set a password to unlock the mnemonic
    let password = Some("random password".to_string());

    // Generate a fresh mnemonic, and from there a privatekey
    let mnemonic: GeneratedKey<_, Segwitv0> =
                Mnemonic::generate((MnemonicType::Words12, Language::English)).unwrap();
    let mnemonic = mnemonic.into_key();
    let xkey: ExtendedKey = (mnemonic, password).into_extended_key().unwrap();
    let xprv = xkey.into_xprv(Network::Testnet).unwrap();

    // Create derived privkey from the above master privkey
    // We use the following derivation paths for receive and change keys
    // receive: "m/84h/1h/0h/0"
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
    
    // Return the keys as a tuple
    (keys[0].clone(), keys[1].clone())
}
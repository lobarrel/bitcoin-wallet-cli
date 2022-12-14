use std::{
    io,
    str::FromStr
};
use tui::{
    backend::{CrosstermBackend},
    Terminal
};
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    style::Stylize,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen},
};
use bdk::{
    bitcoin::{
        Network, 
        secp256k1::Secp256k1,
        consensus::encode::Error,
        util::bip32::{DerivationPath, KeySource},
        Amount,
        Address
    }, 
    sled,
    sled::{Tree},
    blockchain::{
        rpc::wallet_name_from_descriptor,
        ElectrumBlockchain,
        NoopProgress
    },
    electrum_client::Client,
    keys::{
        bip39::{Mnemonic, Language, MnemonicType},
        DescriptorKey::Secret,
        GeneratedKey,
        GeneratableKey,
        ExtendedKey,
        DerivableKey,
        DescriptorKey
    },
    miniscript::Segwitv0,
    Wallet,
    wallet::{
        AddressIndex,
        signer::SignOptions
    }
};



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



fn new_wallet() -> Result<Wallet<ElectrumBlockchain, Tree>, Error> {
    //Electrum client
    let client = Client::new("ssl://electrum.blockstream.info:60002").expect("Connection to Electrum client failed");
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
    let mut datadir = dirs_next::home_dir().expect("Home directory not found"); 
    datadir.push(".bdk-example");
    let database = sled::open(datadir).unwrap();
    let db_tree = database.open_tree(wallet_name.clone()).unwrap();

    //Create the wallet
    let wallet = Wallet::new(
        &receive_desc, 
        Some(&change_desc), 
        Network::Testnet, 
        db_tree, 
        blockchain).unwrap();
    
    Ok(wallet) 
}



fn sync_wallet(wallet: &Wallet<ElectrumBlockchain, Tree>){
    wallet.sync(NoopProgress, None).unwrap();
    println!("{}", format!("Your wallet is synchronized!").green()); 
}



fn get_wallet_address(wallet: &Wallet<ElectrumBlockchain, Tree>){
    let address = wallet.get_address(AddressIndex::New).unwrap().address;
    println!("Address: {}", address);
}



fn get_wallet_balance(wallet: &Wallet<ElectrumBlockchain, Tree>){
    wallet.sync(NoopProgress, None).unwrap();
    let balance = Amount::from_sat(wallet.get_balance().unwrap());
    println!("Balance: {}", balance);
}



fn new_transaction(wallet: &Wallet<ElectrumBlockchain, Tree>) -> Result<(), Error>{
    //Recipient address input
    println!("Recipient address: ");
    let mut arg1 = String::new();
    io::stdin().read_line(&mut arg1).unwrap();
    let recipient_address = Address::from_str(&arg1.trim()).unwrap();

    //Amount input
    println!("Amount (sats): ");
    let mut arg2 = String::new();
    io::stdin().read_line(&mut arg2).unwrap();
    let amount = arg2.trim().parse::<u64>().unwrap();

    //Sync wallet
    wallet.sync(NoopProgress, None).unwrap();

    //Build transaction
    let mut tx_builder = wallet.build_tx();
    tx_builder.set_recipients(vec!((recipient_address.script_pubkey(), amount)));

    // Finalise the transaction and extract PSBT
    let (mut psbt, _) = tx_builder.finish().unwrap();

    // Set signing option
    let signopt = SignOptions {
        assume_height: None,
        ..Default::default()
    };

    // Sign the above PSBT with signing option
    wallet.sign(&mut psbt, signopt).unwrap();

    // Extract the final transaction
    let tx = psbt.extract_tx();
    let txid = tx.txid();

    // Broadcast the transaction
    wallet.broadcast(tx).unwrap();
    println!("{}\nTransaction ID: {}", format!("Transaction completed successfully!").green(), txid); 

    Ok(())
}



fn main(){

    //Create a terminal
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).unwrap();
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).unwrap();

    println!("{}", format!("BITCOIN WALLET\n\n").bold());
    println!("Commands:\nn: create a new wallet\na: get address\nb: get balance\nt: send a transaction\ns: sync the wallet\nq: quit\n");

    if let Event::Key(key) = event::read().unwrap(){
        if let KeyCode::Char('n') = key.code {
            let wallet = new_wallet().unwrap(); 
            println!("{}", format!("Wallet successfully created!").green());

            loop {
                if let Event::Key(key) = event::read().unwrap(){    
                    if let KeyCode::Char('a') = key.code {
                        get_wallet_address(&wallet);
                    }
                    if let KeyCode::Char('b') = key.code {
                        get_wallet_balance(&wallet);
                    }
                    if let KeyCode::Char('t') = key.code {
                        new_transaction(&wallet).unwrap();
                    }
                    if let KeyCode::Char('s') = key.code {
                        sync_wallet(&wallet);
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
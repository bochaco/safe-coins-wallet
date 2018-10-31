# SAFE Coins Wallet

A package which provides the functionality for an altcoin wallet on the [SAFE Network](https://safenetwork.tech).
Any SAFE application can use this package to implement an altcoin wallet by using the
provided API.

This library is used by the [SAFE Wallet App (`safe://safewallet.wow`)](safe://safewallet.wow) available on the SAFE Network ([a live mockup is also available here](https://bochaco.github.io)), and more information about it can be found on [this post in the SAFE Network forum](https://safenetforum.org/t/introducing-safe-wallet-app/11764?u=bochaco).

## The SAFE Altcoins

In the same way that the `safecoin` is expected to be just a `MutableData` on the SAFE Network with a specific tag type reserved for it (i.e. no application will be able to create a MutableData with this tag type but the network itself when rewarding farmers), altcoins on the SAFE Network can also be implemented by creating MutableData's with a predefined tag type, and a mechanism for their supply.
There are several proposals for how altcoins can be implemented and mined/minted on the SAFE Network. Just as an example, a proposal and good discussion can be found in [this thread on the SAFE Network forum](https://safenetforum.org/t/on-creating-safe-alt-coins/7192?u=bochaco).

## The `ThanksCoins`

The ThanksCoin is only a prototype of an altcoin in the SAFE Network, it has not value and it can be minted by any application, it has no value in any market, and can be used only to play with its ThanksCoin wallet.

The following diagram depicts what's the internal data stored in a MutableData so as to be recognised as a `ThanksCoin` by a wallet:

![ThanksCoins Data Entities in the SAFE Network](img/ThanksCoins.png)

The `XORName` is a random address in the SAFE Network which is generated automatically by the SAFE API when creating the Public MutableData.

In order to have a Public MutableData to be recognised by a wallet as a ThanksCoin its `Tag_type` value has to be set to `21082018`.

Finally, since MutableData ownership transfer is not available yet on the SAFE Network, in order to mimic the transfer of ownership, the ThanksCoins contain a single entry which key is `coin-data` and its value is a serialised JSON containing the current (`owner`) and previous owner (`prev_owner`) of the coin.

The first `ThanksCoin` wallet implementation is available within the [SAFE Wallet application (`safe://safewallet.wow`)](safe://safewallet.wow) on the SAFE Network which can be used to play with these ThanksCoins.

#### The SAFE Faucet

In order to receive free ThanksCoins which can be used in the SAFE Wallet app, you can visit the [SAFE Faucet app (`safe://safefaucet.wow`)](safe://safefaucet.wow) on the SAFE Network and claim free coins in exchange of feedback about the SAFE Wallet app. Note you first need to create a ThanksCoin wallet in the SAFE Wallet app to be able to receive your free ThanksCoin's.

## The Coin Wallet

The coin wallet is just a list coins' addresses that are owned by a public key, and it is stored on the SAFE Network as a Private MutableData:

![ThanksCoins Wallet Data Entity in the SAFE Network](img/ThanksCoinWalletPk1.png)

The `Tag_type` for a ThanksCoin wallet is defined to be set to `1012017`.

The address at which the wallet is stored is calculated in a deterministic way so it can be found/shared with any other wallet application which implements the same specification. In the current implementation the address is calculated by applying the `SHA3-256` to the public key owning the coins listed within the wallet. However, any app which wants to access the wallet's Private MutableData will need the encryption keys to be able to read the content, thus the app needs to provide an import mechanism for these encryption keys.

The wallet could alternatively be stored at a random address which is kept private to the user's account. In this case the mechanism to import/use the wallet with another compatible wallet application will need to also consider that the address cannot be determined from the public key but by importing the XOR address of the wallet into the app, along with the encryption keys as mentioned before.

One option is to make use of the MutableData serialisation mechanism provided by the SAFE API, and have the app to keep the serialised version of the wallet's Private MutableData. By doing, so both the XOR address and the encrpytion keys are imported together, and this is the mechanism currently implemented by this package/lib.

As mentioned before, the wallet just contains the list of coins that are owned by the public key the wallet is associated to. In current implementation this is achieved by keeping a single entry in the wallet's MutableData with key `__coins` which value is a list (a serialised JSON format list) of XOR addresses of each of the coins.

If a mechanism like BIP32 is used, it is then needed to have the wallet to keep the list of coins owned by more than a single public key. The wallet's MutableData entries could contain one entry per derived public key which value is the list of coins owned by that public key. The support of this type of wallet is planned to be incorporated in this library/package in the future.

## The TX (transactions) Notifications Inbox

As mentioned above, since the coins on the SAFE Network are just MutableData's owned by one/multiple public key/s, when a coin's ownership is transferred to a different public key, the recipient needs to be notified and provided with the list of addresses of coins that were transferred. This is why the wallet application can expose an inbox to receive such a notifications, this is known as the `TX inbox`:

![TX Inbox Data Entity in the SAFE Network](img/TxInboxPk1.png)

The TX inbox is a Public MutableData which address can be calculated by applying the SHA3 to the public key, and its `Tag_type` is predefined to be `20082018`.

Each transaction is notified by creating a new entry in the TX inbox of the receiving public key, making sure it is encrypted beforehand.

In order to keep the privacy of the transactions to be readable by only the recipient, the TX Inbox contains an entry with key `__tx_enc_pk` and which value contains the public key that can be used to encrypt any notification before it's inserted in the same MutableData.

Each transaction is inserted in the TX inbox MutableData with a random identifier as the entry's key, and it's value containing (as a serialised JSON) the list of addresses of the coins being transferred (`coinIds`), a message string (`msg`) and the timestamp of the transaction (`date`).

The wallet application periodically checks if new entries were inserted into the TX inbox, and in such a case it reads the TX information copying the list of coins into the wallet's MutableData to reflect the new balance.

## The API

Any application can use this package to implement an altcoin wallet without needing to implement the client code to manipulate the coins and the wallet information on the SAFE Network. At the moment, this is in its early stage and only the `ThanksCoin's` are supported, but it is planned to support different type of SAFE Network altcoins, even `safecoins`.

All the functions exposed in this API expect a SAFE App instance as first parameter. This can be obtained by using the SAFE DOM API as described [in the SAFE Network DevHub tutorial](https://hub.safedev.org/platform/web/#authorise-application-and-connect-to-the-safe-network), note that it has to be an SAFE App instance for an authorised and connected session with the network.

#### createWallet( safeApp , publicKey )
This function creates the coin wallet based on the Public Key provided as parameter. As explained [above](#the-coin-wallet), the coin wallet is a private MutableData which address is the result of applying the SHA3 to the `publicKey` value provided.
The value returned by `createWallet` is the serialised MutableData info which contains everything needed to retrieve the data stored in it, including the encryption key. Keeping a copy of the returned value, the coins wallet can be read at any time using `loadWalletData`.

#### loadWalletData( safeApp , serialisedWallet )
In order to read the list of coins stored in a coins wallet, the `loadWalletData` function can be invoked providing the serialised wallet's MutableData info.
This function simply returns an array of coin addresses which are retrieved from the MutableData stored in the SAFE Network.

#### storeCoinsToWallet( safeApp , serialisedWallet , coinsIds )
Whenever the list of coins in the wallet needs to be updated, the `storeCoinsToWallet` function can be invoked providing the updated list of coins (`coinsIds`), along with the serialised wallet's MutableData info (`serialisedWallet`). The list of coins is expected to be an array of the coins' addresses.

#### createTxInbox( safeApp , publicKey )
In order to be able to receive transactions notifications for a coin wallet, a TX Inbox needs to be created as [detailed above](#the-tx-transactions-notifications-inbox).
This function expects the Public Key that owns the coins for which the TX's notifications are to be received to be provided. It creates the public MutableData to accept the notifications, automatically generating the encryption key pair to encrypt/decrypt each of the TX's. This encryption key pair is returned in an object with the following format:
```
{
    pk: <HEX encoded public key>,
    sk: <HEX encoded secret key>
}
```

#### readTxInboxData( safeApp , publicKey , encryptionPk , encryptionSk )
The encryption keys generated when creating the TX Inbox with `createTxInbox` function need to be provided as parameters to this function (`encryptionPk` and `encryptionSk`), along with the Public Key associated to the TX's (`publicKey`). This function returns the list of TX's found in the MutableData kept in the SAFE Network as an array of objects with the following format:
```
{
  id: <TX id randomly generated>,
  coinIds: <list of coins' addresses associated to this TX>,
  msg: <TX textual message>,
  date: <TX timsteamp>
}
```

#### removeTxInboxData( safeApp , publicKey , txsIds )
The TX Inbox can be updated by providing the list of TX's that can be removed from it (`txsIds`) along with the Public Key associated to the TX Inbox (`publicKey`). The list of TX's is expected to have the same format as the one returned by the `readTxInboxData` function above.

#### checkOwnership( safeApp , coinId , publicKey )
Upon receiving a TX notification, the wallet application may want to make sure each of the coins listed in the TX notification are effectively transferred and now owned by the user's Public Key.
This function takes care of making such a verification and it expects the coin address to verify (`coinId`) and the Public Key which the coin is expected to be owned by (`publicKey`). This function fetches the coin from the SAFE Network, verifies the ownership and either reject or resolve the promise based on it. If the ownership is positively confirmed, an object with the following format containing the coin's information is returned:
```
{
  owner: <Public Key of current owner>,
  prev_owner: <Public Key or previous owner>
}
```

#### transferCoin( safeApp , coinId , publicKey , secretKey , recipient )
Transferring a coin to a new recipient can be achieved by simply providing the address of the coin to be transferred (`coinId`), the Secret and Public Key to sign the ownership transfer (`publicKey` and `secretKey`) and the recipient's Public Key (`recipient`).
Note this function doesn't take care of sending the corresponding TX notification which can be done by invoking the `sendTxNotix` function described below.

#### sendTxNotif( safeApp , publicKey , coinsIds , msg )
Sending a TX notifications is very simple, the Public Key which now owns the coins that were transferred (`publicKey`), the list of coins addresses that were transferred (`coinsIds`), and a textual message for the notification (`msg`), it's all that is required by this function to be able to encrypt the corresponding TX notification and store it in the recipient's TX Inbox.

## Use Cases diagrams
TODO
- Create a wallet
- Read TX inbox for new TX
- Read/Update wallet
- Transfer coin and send TX notifications


## How to use it
Install the `npm` dependency in your project:
```
npm i --save safe-coins-wallet
```
Then use the API:
```js
const safeCoinsWallet = require('safe-coins-wallet');

safeCoinsWallet.createWallet(...)
  .then(function (wallet) { ... });
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

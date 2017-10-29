/*
  Module which takes care of the SAFEnet altcoins wallet functioning
*/
const crypto = require('crypto');

const TAG_TYPE_WALLET = 1012017;
const TAG_TYPE_WALLET_TX_INBOX = 20082018;
const TAG_TYPE_THANKS_COIN = 21082018;

const COIN_ENTRY_KEY_DATA = 'coin-data';

const TX_INBOX_ENTRY_KEY_PK = '__tx_enc_pk';
const TX_INBOX_METADATA_NAME = 'ThanksCoins inbox';
const TX_INBOX_METADATA_DESC = 'Container to receive notifications of ThanksCoins transactions';

const WALLET_ENTRY_KEY_COINS = '__coins';
const WALLET_METADATA_NAME = 'ThanksCoins Wallet';
const WALLET_METADATA_DESC = 'Container to store the list of ThanksCoins addresses owned';

const ENTRY_KEY_MD_METADATA = '_metadata';

// Generic Helper functions
const _fromArrayBuffer = (buf) => String.fromCharCode.apply(null, new Uint8Array(buf));
const _genXorName = (appHandle, id) => window.safeCrypto.sha3Hash(appHandle, id);

// Altcoin Wallet management functions
const _readEncryptedEntry = (mdHandle, key) => {
  return window.safeMutableData.encryptKey(mdHandle, key)
    .then((encKey) => window.safeMutableData.get(mdHandle, encKey))
    .then((encValue) => window.safeMutableData.decrypt(mdHandle, encValue.buf));
}

const _insertEntriesEncrypted = (appHandle, mdHandle, data) => {
  return window.safeMutableData.newMutation(appHandle)
    .then((mutHandle) => Promise.all(Object.keys(data).map((key) => {
        return window.safeMutableData.encryptKey(mdHandle, key)
          .then((encKey) => window.safeMutableData.encryptValue(mdHandle, data[key])
            .then((encValue) => window.safeMutableDataMutation.insert(mutHandle, encKey, encValue))
          )
      }))
      .then(() => window.safeMutableData.applyEntriesMutation(mdHandle, mutHandle))
      .then(() => window.safeMutableDataMutation.free(mutHandle))
    );
}

const createWallet = (appHandle, pk) => {
  console.log("Creating the coin wallet...");
  const emptyCoins = {
    [WALLET_ENTRY_KEY_COINS]: JSON.stringify([])
  }
  return window.safeCrypto.generateEncKeyPair(appHandle)
    .then((keyPairHandle) => window.safeCryptoKeyPair.getSecEncKey(keyPairHandle)
      .then((secEncKeyHandle) =>  window.safeCryptoSecEncKey.getRaw(secEncKeyHandle)
        .then((secEncKey) => window.safeCrypto.generateNonce(appHandle)
          .then((nonce) => _genXorName(appHandle, pk)
            .then((xorName) => window.safeMutableData.newPrivate(appHandle, xorName, TAG_TYPE_WALLET, secEncKey.buffer, nonce.buffer))
            .then((inboxHandle) => window.safeMutableData.quickSetup(inboxHandle, {}, WALLET_METADATA_NAME, WALLET_METADATA_DESC)) //TODO: support the case that it exists already
            .then((inboxHandle) => _insertEntriesEncrypted(appHandle, inboxHandle, emptyCoins)
              .then(() => window.safeMutableData.serialise(inboxHandle))
              .then((serialisedWallet) => {
                window.safeCryptoKeyPair.free(keyPairHandle)
                window.safeCryptoSecEncKey.free(secEncKeyHandle);
                let walletArr = new Uint8Array(serialisedWallet);
                return walletArr.toString();
              })
            )
          )
        )
      )
    );
}

const _deserialiseArray = (strOrBuffer) => {
  let arrItems = strOrBuffer.split(',');
  return Uint8Array.from(arrItems);
}

const loadWalletData = (appHandle, serialisedWallet) => {
  // We store the wallet inbox at the sha3 hash value of its PublicKey
  // so it's easy to find by other wallet apps to transfer coins.
  console.log("Reading the coin wallet info...");
  return window.safeMutableData.fromSerial(appHandle, _deserialiseArray(serialisedWallet))
    .then((walletHandle) => _readEncryptedEntry(walletHandle, WALLET_ENTRY_KEY_COINS))
    .then((coins) => JSON.parse(_fromArrayBuffer(coins)));
}

const storeCoinsToWallet = (appHandle, serialisedWallet, coins) => {
  console.log("Saving coins in the wallet on the network...");
  return window.safeMutableData.fromSerial(appHandle, _deserialiseArray(serialisedWallet))
    .then((walletHandle) => window.safeMutableData.encryptKey(walletHandle, WALLET_ENTRY_KEY_COINS)
      .then((encKey) => window.safeMutableData.get(walletHandle, encKey)
        .then((currentCoins) => window.safeMutableData.newMutation(appHandle)
          .then((mutHandle) => window.safeMutableData.encryptValue(walletHandle, JSON.stringify(coins))
            .then((encValue) => window.safeMutableDataMutation.update(mutHandle, encKey, encValue, currentCoins.version + 1)
              .then(() => window.safeMutableData.applyEntriesMutation(walletHandle, mutHandle))
              .then(() => window.safeMutableDataMutation.free(mutHandle))
            )
          )
        )
      )
    );
}

// TX Inbox management functions
const _genKeyPair = (appHandle) => {
  let rawKeyPair = {};
  return window.safeCrypto.generateEncKeyPair(appHandle)
    .then((keyPairHandle) => window.safeCryptoKeyPair.getPubEncKey(keyPairHandle)
      .then((pubEncKeyHandle) => window.safeCryptoPubEncKey.getRaw(pubEncKeyHandle)
        .then((rawPubEncKey) => {
          window.safeCryptoPubEncKey.free(pubEncKeyHandle);
          rawKeyPair.pk = rawPubEncKey.buffer.toString('hex');
          return;
        })
      )
      .then(() => window.safeCryptoKeyPair.getSecEncKey(keyPairHandle))
      .then((secEncKeyHandle) => window.safeCryptoSecEncKey.getRaw(secEncKeyHandle)
        .then(rawSecEncKey => {
          window.safeCryptoSecEncKey.free(secEncKeyHandle);
          window.safeCryptoKeyPair.free(keyPairHandle);
          rawKeyPair.sk = rawSecEncKey.buffer.toString('hex');
          return rawKeyPair;
        })
      )
    )
}

const createTxInbox = (appHandle, pk) => {
  console.log("Creating TX inbox...", pk);
  let baseInbox;
  let encKeys;
  let inboxHandle;
  let permSetHandle;
  return _genKeyPair(appHandle)
    .then((keys) => {
      encKeys = keys;
      baseInbox = {
        [TX_INBOX_ENTRY_KEY_PK]: encKeys.pk
      };
      return _genXorName(appHandle, pk);
    })
    .then((xorName) => window.safeMutableData.newPublic(appHandle, xorName, TAG_TYPE_WALLET_TX_INBOX))
    .then((mdHandle) => window.safeMutableData.quickSetup(mdHandle, baseInbox, TX_INBOX_METADATA_NAME, TX_INBOX_METADATA_DESC))
    .then((mdHandle) => inboxHandle = mdHandle)
    .then(() => window.safeMutableData.newPermissionSet(appHandle))
    .then((pmSetHandle) => permSetHandle = pmSetHandle)
    .then(() => window.safeMutableDataPermissionsSet.setAllow(permSetHandle, 'Insert'))
    .then(() => window.safeMutableData.setUserPermissions(inboxHandle, null, permSetHandle, 1))
    .then(() => window.safeMutableDataPermissionsSet.free(permSetHandle))
    .then(() => {
      window.safeMutableData.free(inboxHandle);
      return encKeys;
    });
}

const _encrypt = (appHandle, input, pk) => {
  if(Array.isArray(input)) {
    input = input.toString();
  }

  return window.safeCrypto.pubEncKeyKeyFromRaw(appHandle, Buffer.from(pk, 'hex'))
    .then((pubEncKeyHandle) => window.safeCryptoPubEncKey.encryptSealed(pubEncKeyHandle, input)
      .then((encrypted) => {
        window.safeCryptoPubEncKey.free(pubEncKeyHandle);
        return encrypted;
      })
    );
};

const _decryptTxs = (appHandle, encryptedTxs, encPk, encSk) => {
  return Promise.all(encryptedTxs.map((encTx) => {
    const rawPk = Buffer.from(encPk, 'hex');
    const rawSk = Buffer.from(encSk, 'hex');
    return window.safeCrypto.generateEncKeyPairFromRaw(appHandle, rawPk, rawSk)
      .then((keyPairHandle) => window.safeCryptoKeyPair.decryptSealed(keyPairHandle, encTx.txInfo)
        .then((decrypted) => {
          window.safeCryptoKeyPair.free(keyPairHandle);
          const parsedTxInfo = JSON.parse(_fromArrayBuffer(decrypted));
          return Object.assign({ id: encTx.id }, parsedTxInfo);
        })
      );
  }));
}

const readTxInboxData = (appHandle, pk, encPk, encSk) => {
  let encryptedTxs = [];
  return _genXorName(appHandle, pk)
    .then((xorName) => window.safeMutableData.newPublic(appHandle, xorName, TAG_TYPE_WALLET_TX_INBOX))
    .then((inboxHandle) => window.safeMutableData.getEntries(inboxHandle)
      .then((entriesHandle) => window.safeMutableDataEntries.forEach(entriesHandle, (key, value) => {
          const id = _fromArrayBuffer(key);
          const txInfo = value.buf;
          // Ignore the Public encryption key entry, the metadata entry
          // and soft-deleted entries.
          if (id !== TX_INBOX_ENTRY_KEY_PK && id !== ENTRY_KEY_MD_METADATA
              && txInfo.length > 0) {
            encryptedTxs.push({ id, txInfo });
          }
        })
        .then(() => _decryptTxs(appHandle, encryptedTxs, encPk, encSk))
        .then((decryptedTxs) => {
          window.safeMutableDataEntries.free(entriesHandle);
          window.safeMutableData.free(inboxHandle);
          return decryptedTxs;
        })
      )
    );
}

const removeTxInboxData = (appHandle, pk, txs) => {
  return window.safeMutableData.newMutation(appHandle)
    .then((mutHandle) => Promise.all(txs.map((tx) => window.safeMutableDataMutation.remove(mutHandle, tx.id, 1)))
      .then(() => _genXorName(appHandle, pk))
      .then((xorName) => window.safeMutableData.newPublic(appHandle, xorName, TAG_TYPE_WALLET_TX_INBOX))
      .then((txInboxHandle) => window.safeMutableData.applyEntriesMutation(txInboxHandle, mutHandle)
        .then(() => window.safeMutableData.free(txInboxHandle))
      )
      .then(() => window.safeMutableDataMutation.free(mutHandle))
    );
}

const sendTxNotif = (appHandle, pk, coinIds, msg) => {
  const txId = crypto.randomBytes(16).toString('hex');
  const tx = {
    coinIds: coinIds,
    msg: msg,
    date: (new Date()).toUTCString()
  }
  const txNotif = JSON.stringify(tx);

  console.log("Sending TX notification to recipient. TX id: ", txId);
  return _genXorName(appHandle, pk)
    .then((xorName) => window.safeMutableData.newPublic(appHandle, xorName, TAG_TYPE_WALLET_TX_INBOX))
    .then((txInboxHandle) => window.safeMutableData.get(txInboxHandle, TX_INBOX_ENTRY_KEY_PK)
      .then((encPk) => _encrypt(appHandle, txNotif, encPk.buf.toString()))
      .then((encryptedTx) => window.safeMutableData.newMutation(appHandle)
        .then((mutHandle) => window.safeMutableDataMutation.insert(mutHandle, txId, encryptedTx)
          .then(() => window.safeMutableData.applyEntriesMutation(txInboxHandle, mutHandle)
            .then(() => window.safeMutableData.free(txInboxHandle))
          )
          .then(() => window.safeMutableDataMutation.free(mutHandle))
        )
      )
    );
}

const _checkOwnership = (coin, pk) => {
  const coinData = JSON.parse(coin);
  console.log("Coin data: ", coinData);
  if (coinData.owner !== pk) {
    throw Error ("Ownership doesn't match", pk, coinData);
  }
  return Promise.resolve(coinData);
}

const checkOwnership = (appHandle, coinId, pk) => {
  console.log("Reading coin data...", pk, coinId);
  return window.safeMutableData.newPublic(appHandle, Buffer.from(coinId, 'hex'), TAG_TYPE_THANKS_COIN)
    .then((coinHandle) => window.safeMutableData.get(coinHandle, COIN_ENTRY_KEY_DATA)
      .then((coin) => {
        window.safeMutableData.free(coinHandle);
        return _checkOwnership(coin.buf.toString(), pk);
      })
    );
}

const transferCoin = (appHandle, coinId, pk, sk, recipient) => {
  console.log("Transfering coin's ownership in the network...", coinId, recipient);

  return window.safeMutableData.newPublic(appHandle, Buffer.from(coinId, 'hex'), TAG_TYPE_THANKS_COIN)
    .then((coinHandle) => window.safeMutableData.get(coinHandle, COIN_ENTRY_KEY_DATA)
      .then((coin) => _checkOwnership(coin.buf.toString(), pk)
        .then((coinData) => {
          coinData.owner = recipient;
          coinData.prev_owner = pk;
          console.log("Coin's new ownership: ", coinData);
          return window.safeMutableData.newMutation(appHandle)
            .then((mutHandle) => window.safeMutableDataMutation.update(mutHandle, COIN_ENTRY_KEY_DATA, JSON.stringify(coinData), coin.version + 1)
              .then(() => window.safeMutableData.applyEntriesMutation(coinHandle, mutHandle))
              .then(() => window.safeMutableDataMutation.free(mutHandle))
            );
        })
      )
      .then(() => window.safeMutableData.free(coinHandle))
    );
}

module.exports = {
  createWallet,
  loadWalletData,
  storeCoinsToWallet,
  createTxInbox,
  readTxInboxData,
  removeTxInboxData,
  sendTxNotif,
  checkOwnership,
  transferCoin
};

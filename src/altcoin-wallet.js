/*
  Module which takes care of the SAFEnet altcoins wallet functioning
*/
const crypto = require('crypto');

const USER_ANYONE = null;
const ACTION_INSERT = 'Insert';

const TAG_TYPE_WALLET = 1012017;
const TAG_TYPE_WALLET_TX_INBOX = 20082018;
const TAG_TYPE_THANKS_COIN = 21082018;

const COIN_ENTRY_KEY_DATA = 'coin-data';

const TX_INBOX_ENTRY_KEY_PK = '__tx_enc_pk';
const TX_INBOX_METADATA_NAME = 'ThanksCoins TX Inbox';
const TX_INBOX_METADATA_DESC = 'Container to receive notifications of ThanksCoins transactions';

const WALLET_ENTRY_KEY_COINS = '__coins';
const WALLET_METADATA_NAME = 'ThanksCoins Wallet';
const WALLET_METADATA_DESC = 'Container to store the list of ThanksCoins addresses owned';

const ENTRY_KEY_MD_METADATA = '_metadata';

// Generic Helper functions
const _fromArrayBuffer = (buf) => String.fromCharCode.apply(null, new Uint8Array(buf));
const _genXorName = (appHandle, id) => window.safeCrypto.sha3Hash(appHandle, id);

// Altcoin Wallet management functions
const _readEncryptedEntry = async (mdHandle, key) => {
  const encKey = await window.safeMutableData.encryptKey(mdHandle, key);
  const encValue = await window.safeMutableData.get(mdHandle, encKey);
  return window.safeMutableData.decrypt(mdHandle, encValue.buf);
}

const _insertEntriesEncrypted = async (appHandle, mdHandle, data) => {
  const mutHandle = await window.safeMutableData.newMutation(appHandle);
  await Promise.all(Object.keys(data).map(async (key) => {
      const encKey = await window.safeMutableData.encryptKey(mdHandle, key);
      const encValue = await window.safeMutableData.encryptValue(mdHandle, data[key]);
      return window.safeMutableDataMutation.insert(mutHandle, encKey, encValue);
    }));

  await window.safeMutableData.applyEntriesMutation(mdHandle, mutHandle);
  window.safeMutableDataMutation.free(mutHandle);
}

const createWallet = async (appHandle, pk) => {
  console.log("Creating the coin wallet...");
  const emptyCoins = {
    [WALLET_ENTRY_KEY_COINS]: JSON.stringify([])
  };

  const keyPairHandle = await window.safeCrypto.generateEncKeyPair(appHandle);
  const secEncKeyHandle = await window.safeCryptoEncKeyPair.getSecEncKey(keyPairHandle);
  const secEncKey = await window.safeCryptoSecEncKey.getRaw(secEncKeyHandle);
  const nonce = await window.safeCrypto.generateNonce(appHandle);
  const xorName = await _genXorName(appHandle, pk);
  const walletHandle = await window.safeMutableData.newPrivate(appHandle, xorName, TAG_TYPE_WALLET, secEncKey.buffer, nonce.buffer);
  await window.safeMutableData.quickSetup(walletHandle, {}, WALLET_METADATA_NAME, WALLET_METADATA_DESC); //TODO: support the case that it exists already
  await _insertEntriesEncrypted(appHandle, walletHandle, emptyCoins);
  const serialisedWallet = await window.safeMutableData.serialise(walletHandle);
  window.safeCryptoEncKeyPair.free(keyPairHandle)
  window.safeCryptoSecEncKey.free(secEncKeyHandle);
  window.safeMutableData.free(walletHandle);
  const walletArr = new Uint8Array(serialisedWallet);
  return walletArr.toString();
}

const _deserialiseArray = (strOrBuffer) => {
  let arrItems = strOrBuffer.split(',');
  return Uint8Array.from(arrItems);
}

const loadWalletData = async (appHandle, serialisedWallet) => {
  console.log("Reading the coin wallet info...");
  const deserialisedWallet = _deserialiseArray(serialisedWallet);
  const walletHandle = await window.safeMutableData.fromSerial(appHandle, deserialisedWallet);
  const coins = await _readEncryptedEntry(walletHandle, WALLET_ENTRY_KEY_COINS);
  window.safeMutableData.free(walletHandle);
  return JSON.parse(_fromArrayBuffer(coins));
}

const storeCoinsToWallet = async (appHandle, serialisedWallet, coins) => {
  console.log("Saving coins in the wallet on the network...");
  const walletHandle = await window.safeMutableData.fromSerial(appHandle, _deserialiseArray(serialisedWallet));
  const encKey = await window.safeMutableData.encryptKey(walletHandle, WALLET_ENTRY_KEY_COINS);
  const currentCoins = await window.safeMutableData.get(walletHandle, encKey);
  const mutHandle = await window.safeMutableData.newMutation(appHandle);
  const encValue = await window.safeMutableData.encryptValue(walletHandle, JSON.stringify(coins));
  await window.safeMutableDataMutation.update(mutHandle, encKey, encValue, currentCoins.version + 1);
  await window.safeMutableData.applyEntriesMutation(walletHandle, mutHandle);
  window.safeMutableData.free(walletHandle);
  window.safeMutableDataMutation.free(mutHandle);
}

// TX Inbox management functions
const _genKeyPair = async (appHandle) => {
  let rawKeyPair = {};
  const keyPairHandle = await window.safeCrypto.generateEncKeyPair(appHandle);
  const pubEncKeyHandle = await window.safeCryptoEncKeyPair.getPubEncKey(keyPairHandle);
  const rawPubEncKey = await window.safeCryptoPubEncKey.getRaw(pubEncKeyHandle);
  window.safeCryptoPubEncKey.free(pubEncKeyHandle);
  rawKeyPair.pk = rawPubEncKey.buffer.toString('hex');
  const secEncKeyHandle = await window.safeCryptoEncKeyPair.getSecEncKey(keyPairHandle);
  const rawSecEncKey = await window.safeCryptoSecEncKey.getRaw(secEncKeyHandle);
  window.safeCryptoSecEncKey.free(secEncKeyHandle);
  window.safeCryptoEncKeyPair.free(keyPairHandle);
  rawKeyPair.sk = rawSecEncKey.buffer.toString('hex');
  return rawKeyPair;
}

const createTxInbox = async (appHandle, pk) => {
  console.log("Creating TX inbox...");
  const encKeys = await _genKeyPair(appHandle);
  const baseInbox = {
    [TX_INBOX_ENTRY_KEY_PK]: encKeys.pk
  };
  const xorName = await _genXorName(appHandle, pk);
  const inboxHandle = await window.safeMutableData.newPublic(appHandle, xorName, TAG_TYPE_WALLET_TX_INBOX);
  await window.safeMutableData.quickSetup(inboxHandle, baseInbox, TX_INBOX_METADATA_NAME, TX_INBOX_METADATA_DESC);
  const permSet = [ ACTION_INSERT ];
  await window.safeMutableData.setUserPermissions(inboxHandle, USER_ANYONE, permSet, 1);
  window.safeMutableData.free(inboxHandle);
  return encKeys;
}

const _encrypt = async (appHandle, input, pk) => {
  if (Array.isArray(input)) {
    input = input.toString();
  }

  const pubEncKeyHandle = await window.safeCrypto.pubEncKeyFromRaw(appHandle, Buffer.from(pk, 'hex'));
  const encrypted = await window.safeCryptoPubEncKey.encryptSealed(pubEncKeyHandle, input);
  window.safeCryptoPubEncKey.free(pubEncKeyHandle);
  return encrypted;
};

const _decryptTxs = async (appHandle, encryptedTxs, encPk, encSk) => {
  return Promise.all(encryptedTxs.map(async (encTx) => {
      const rawPk = Buffer.from(encPk, 'hex');
      const rawSk = Buffer.from(encSk, 'hex');
      const keyPairHandle = await window.safeCrypto.generateEncKeyPairFromRaw(appHandle, rawPk, rawSk);
      const decrypted = await window.safeCryptoEncKeyPair.decryptSealed(keyPairHandle, encTx.txInfo);
      window.safeCryptoEncKeyPair.free(keyPairHandle);
      const parsedTxInfo = JSON.parse(_fromArrayBuffer(decrypted));
      return { id: encTx.id , ...parsedTxInfo };
    }));
}

const readTxInboxData = async (appHandle, pk, encPk, encSk) => {
  let encryptedTxs = [];
  const xorName = await _genXorName(appHandle, pk);
  const inboxHandle = await window.safeMutableData.newPublic(appHandle, xorName, TAG_TYPE_WALLET_TX_INBOX);
  const entriesHandle = await window.safeMutableData.getEntries(inboxHandle);
  await window.safeMutableDataEntries.forEach(entriesHandle, (key, value) => {
      const id = _fromArrayBuffer(key);
      const txInfo = value.buf;
      // Ignore the Public encryption key entry, the metadata entry, and soft-deleted entries.
      if (id !== TX_INBOX_ENTRY_KEY_PK && id !== ENTRY_KEY_MD_METADATA && txInfo.length > 0) {
        encryptedTxs.push({ id, txInfo });
      }
    });
  const decryptedTxs = await _decryptTxs(appHandle, encryptedTxs, encPk, encSk);
  window.safeMutableDataEntries.free(entriesHandle);
  window.safeMutableData.free(inboxHandle);
  return decryptedTxs;
}

const removeTxInboxData = async (appHandle, pk, txs) => {
  const mutHandle = await window.safeMutableData.newMutation(appHandle);
  await Promise.all(txs.map((tx) => window.safeMutableDataMutation.remove(mutHandle, tx.id, 1)));
  const xorName = await _genXorName(appHandle, pk);
  const txInboxHandle = await window.safeMutableData.newPublic(appHandle, xorName, TAG_TYPE_WALLET_TX_INBOX);
  await window.safeMutableData.applyEntriesMutation(txInboxHandle, mutHandle);
  window.safeMutableData.free(txInboxHandle);
  window.safeMutableDataMutation.free(mutHandle);
}

const sendTxNotif = async (appHandle, pk, coinIds, msg) => {
  const txId = crypto.randomBytes(16).toString('hex');
  const tx = {
    coinIds: coinIds,
    msg: msg,
    date: (new Date()).toUTCString()
  };
  const txNotif = JSON.stringify(tx);

  console.log("Sending TX notification to recipient. TX id: ", txId);
  const xorName = await _genXorName(appHandle, pk);
  const txInboxHandle = await window.safeMutableData.newPublic(appHandle, xorName, TAG_TYPE_WALLET_TX_INBOX);
  const encPk = await window.safeMutableData.get(txInboxHandle, TX_INBOX_ENTRY_KEY_PK);
  const encryptedTx = await _encrypt(appHandle, txNotif, encPk.buf.toString());
  const mutHandle = await window.safeMutableData.newMutation(appHandle);
  await window.safeMutableDataMutation.insert(mutHandle, txId, encryptedTx);
  await window.safeMutableData.applyEntriesMutation(txInboxHandle, mutHandle);
  window.safeMutableData.free(txInboxHandle);
  window.safeMutableDataMutation.free(mutHandle);
}

const _checkOwnership = (coin, pk) => {
  const coinData = JSON.parse(coin);
  console.log("Coin data: ", coinData);
  // TODO: implement ownership check using sign keys
  if (coinData.owner !== pk) {
    throw Error ("Ownership doesn't match", pk, coinData);
  }
  return Promise.resolve(coinData);
}

const _fetchCoin = async (appHandle, coinId) => {
  const coinHandle = await window.safeMutableData.newPublic(appHandle, Buffer.from(coinId, 'hex'), TAG_TYPE_THANKS_COIN);
  const coin = await window.safeMutableData.get(coinHandle, COIN_ENTRY_KEY_DATA);
  return { coin, coinHandle };
}

const checkOwnership = async (appHandle, coinId, pk) => {
  console.log("Reading coin data...", pk, coinId);
  const { coin, coinHandle } = await _fetchCoin(appHandle, coinId);
  window.safeMutableData.free(coinHandle);
  return _checkOwnership(coin.buf.toString(), pk);
}

const transferCoin = async (appHandle, coinId, pk, sk, recipient) => {
  console.log("Transfering coin's ownership in the network...", coinId, recipient);
  const { coin, coinHandle } = await _fetchCoin(appHandle, coinId);
  let coinData = await _checkOwnership(coin.buf.toString(), pk);
  coinData.owner = recipient;
  coinData.prev_owner = pk;
  console.log("Coin's new ownership: ", coinData);
  const mutHandle = await window.safeMutableData.newMutation(appHandle);
  await window.safeMutableDataMutation.update(mutHandle, COIN_ENTRY_KEY_DATA, JSON.stringify(coinData), coin.version + 1);
  await window.safeMutableData.applyEntriesMutation(coinHandle, mutHandle);
  window.safeMutableDataMutation.free(mutHandle);
  window.safeMutableData.free(coinHandle);
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

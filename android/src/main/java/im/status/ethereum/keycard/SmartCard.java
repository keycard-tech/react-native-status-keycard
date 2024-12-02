package im.status.ethereum.keycard;

import android.app.Activity;
import android.content.res.AssetManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.nfc.NfcAdapter;
import android.util.EventLog;
import android.util.Log;

import com.facebook.react.bridge.*;
import com.facebook.react.modules.core.DeviceEventManagerModule;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Scanner;
import java.util.Map;
import java.util.HashMap;
import java.util.Iterator;

import im.status.keycard.applet.RecoverableSignature;
import im.status.keycard.applet.Certificate;
import im.status.keycard.globalplatform.GlobalPlatformCommandSet;
import im.status.keycard.io.APDUException;
import im.status.keycard.io.APDUResponse;
import im.status.keycard.io.CardChannel;
import im.status.keycard.io.CardListener;
import im.status.keycard.android.NFCCardManager;
import im.status.keycard.applet.ApplicationStatus;
import im.status.keycard.applet.BIP32KeyPair;
import im.status.keycard.applet.Mnemonic;
import im.status.keycard.applet.Metadata;
import im.status.keycard.applet.CashCommandSet;
import im.status.keycard.applet.KeycardCommandSet;
import im.status.keycard.applet.Pairing;
import im.status.keycard.applet.ApplicationInfo;
import im.status.keycard.applet.KeyPath;

import org.bouncycastle.util.encoders.Hex;

public class SmartCard extends BroadcastReceiver implements CardListener {
    private NFCCardManager cardManager;
    private NfcAdapter nfcAdapter;
    private CardChannel cardChannel;
    private EventEmitter eventEmitter;
    private static final String TAG = "SmartCard";
    private Boolean started = false;
    private Boolean listening = false;
    private HashMap<String, String> pairings;
    private String[] caPubKeys;
    private String skipVerificationUID;

    private static final String MASTER_PATH = "m";
    private static final String ROOT_PATH = "m/44'/60'/0'/0";
    private static final String WALLET_PATH = "m/44'/60'/0'/0/0";
    private static final String WHISPER_PATH = "m/43'/60'/1581'/0'/0";
    private static final String ENCRYPTION_PATH = "m/43'/60'/1581'/1'/0";
    private static final int WORDS_LIST_SIZE = 2048;

    public SmartCard(ReactContext reactContext) {
        this.cardManager = new NFCCardManager();
        this.cardManager.setCardListener(this);
        this.eventEmitter = new EventEmitter(reactContext);
        this.pairings = new HashMap<>();
        this.caPubKeys = new String[0];
        this.skipVerificationUID = "";
    }

    public String getName() {
        return "SmartCard";
    }

    public void log(String s) {
        Log.d(TAG, s);
    }

    public boolean start(Activity activity) {
        if(activity == null) {
            return false;
        }

        if (!started) {
            this.nfcAdapter = NfcAdapter.getDefaultAdapter(activity.getBaseContext());
            this.cardManager.start();
            started = true;
        }

        if (this.nfcAdapter != null) {
            IntentFilter filter = new IntentFilter(NfcAdapter.ACTION_ADAPTER_STATE_CHANGED);
            activity.registerReceiver(this, filter);
            nfcAdapter.enableReaderMode(activity, this.cardManager, NfcAdapter.FLAG_READER_NFC_A | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK, null);
            return true;
        } else {
            log("not support in this device");
            return false;
        }
    }

    public void stop(Activity activity) {
        if (activity != null && nfcAdapter != null) {
            nfcAdapter.disableReaderMode(activity);
        }
    }

    public void startNFC() {
        this.listening = true;
        if (this.cardChannel != null) {
            eventEmitter.emit("keyCardOnConnected", null);
        }
    }

    public void stopNFC() {
        this.listening = false;
    }

    @Override
    public void onConnected(final CardChannel channel) {
        this.cardChannel = channel;

        if (this.listening) {
            eventEmitter.emit("keyCardOnConnected", null);
        }
    }

    @Override
    public void onDisconnected() {
        this.cardChannel = null;
        
        if (this.listening) {
            eventEmitter.emit("keyCardOnDisconnected", null);
        }
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        final int state = intent.getIntExtra(NfcAdapter.EXTRA_ADAPTER_STATE, NfcAdapter.STATE_OFF);
        boolean on = false;
        switch (state) {
            case NfcAdapter.STATE_ON:
                eventEmitter.emit("keyCardOnNFCEnabled", null);
                log("NFC ON");
                break;
            case NfcAdapter.STATE_OFF:
                eventEmitter.emit("keyCardOnNFCDisabled", null);
                log("NFC OFF");
                break;
            default:
                log("other");
        }
    }

    public boolean isNfcSupported(Activity activity) {
        return activity != null && activity.getPackageManager().hasSystemFeature(PackageManager.FEATURE_NFC);
    }

    public boolean isNfcEnabled() {
        if (nfcAdapter != null) {
            return nfcAdapter.isEnabled();
        } else {
            return false;
        }
    }

    public SmartCardSecrets init(final String userPin) throws IOException, APDUException, NoSuchAlgorithmException, InvalidKeySpecException {
        KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        cmdSet.select().checkOK();

        eventEmitter.emit("keycardInstallationProgress", 0.90);

        SmartCardSecrets s = SmartCardSecrets.generate(userPin);

        eventEmitter.emit("keycardInstallationProgress", 0.93);

        cmdSet.init(s.getPin(), s.getPuk(), s.getPairingPassword()).checkOK();

        eventEmitter.emit("keycardInstallationProgress", 1.0);

        return s;
    }

    public String pair(String pairingPassword) throws IOException, APDUException {
        KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        Log.i(TAG, "Applet selection successful");

        // First thing to do is selecting the applet on the card.
        ApplicationInfo info = new ApplicationInfo(cmdSet.select().checkOK().getData());
        String instanceUID = Hex.toHexString(info.getInstanceUID());
        Log.i(TAG, "Instance UID: " + instanceUID);
        Log.i(TAG, "Key UID: " + Hex.toHexString(info.getKeyUID()));
        Log.i(TAG, "Secure channel public key: " + Hex.toHexString(info.getSecureChannelPubKey()));
        Log.i(TAG, "Application version: " + info.getAppVersionString());
        Log.i(TAG, "Free pairing slots: " + info.getFreePairingSlots());

        cmdSet.autoPair(pairingPassword);

        Pairing pairing = cmdSet.getPairing();
        pairings.put(instanceUID, pairing.toBase64());
        return pairing.toBase64();
    }

    public String generateMnemonic(String words) throws IOException, APDUException {
        KeycardCommandSet cmdSet = securedCommandSet();

        Mnemonic mnemonic = new Mnemonic(cmdSet.generateMnemonic(KeycardCommandSet.GENERATE_MNEMONIC_12_WORDS).checkOK().getData());

        Scanner scanner = new Scanner(words);
        ArrayList<String> list = new ArrayList<>();
        while(scanner.hasNextLine()) {
            list.add(scanner.nextLine());
        }
        scanner.close();

        String [] wordsList = list.toArray(new String[WORDS_LIST_SIZE]);
        mnemonic.setWordlist(wordsList);

        return mnemonic.toMnemonicPhrase();
    }

    public void saveMnemonic(String mnemonic, String pin) throws IOException, APDUException {
        KeycardCommandSet cmdSet = authenticatedCommandSet(pin);

        byte[] seed = Mnemonic.toBinarySeed(mnemonic, "");
        cmdSet.loadKey(seed);

        log("seed loaded to card");
    }

    public boolean tryDefaultPairing(KeycardCommandSet cmdSet, String instanceUID, WritableMap cardInfo) throws IOException {
        try {
            cmdSet.autoPair("KeycardDefaultPairing");

            Pairing pairing = cmdSet.getPairing();
            pairings.put(instanceUID, pairing.toBase64());
            cardInfo.putString("new-pairing", pairing.toBase64());

            openSecureChannel(cmdSet);
            return true;
        } catch(APDUException e) {
            Log.i(TAG, "autoOpenSecureChannel failed: " + e.getMessage());
            return false;
        }
    }

    private boolean verifyAuthenticity(KeycardCommandSet cmdSet, String instanceUID) throws IOException {
        if ((this.caPubKeys.length == 0) || instanceUID.equals(this.skipVerificationUID)) {
            this.skipVerificationUID = "";
            return true;
        }

        try {
            byte[] rawChallenge = SmartCardSecrets.randomBytes(32);
            byte[] data = cmdSet.identifyCard(rawChallenge).checkOK().getData();
            byte[] caPubKey = Certificate.verifyIdentity(rawChallenge, data);

            if (caPubKey == null) {
                return false;
            }

            String caStr = Hex.toHexString(caPubKey);
            for (int i = 0; i < this.caPubKeys.length; i++) {
                if (caStr.equals(this.caPubKeys[i])) {
                    return true;
                }
            }
        } catch(APDUException e) {
            Log.i(TAG, "verification failed: " + e.getMessage());
        }

        return false;
    }

    public WritableMap getApplicationInfo() throws IOException, APDUException {
        KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        ApplicationInfo info = new ApplicationInfo(cmdSet.select().checkOK().getData());

        Log.i(TAG, "Card initialized? " + info.isInitializedCard());

        WritableMap cardInfo = Arguments.createMap();
        cardInfo.putBoolean("initialized?", info.isInitializedCard());

        if (info.isInitializedCard()) {
            String instanceUID = Hex.toHexString(info.getInstanceUID());
            String cardName = getCardNameOrDefault(cmdSet);
            cardInfo.putString("card-name", cardName);

            Log.i(TAG, "Instance UID: " + instanceUID);
            Log.i(TAG, "Card name: " + cardName);
            Log.i(TAG, "Key UID: " + Hex.toHexString(info.getKeyUID()));
            Log.i(TAG, "Secure channel public key: " + Hex.toHexString(info.getSecureChannelPubKey()));
            Log.i(TAG, "Application version: " + info.getAppVersionString());
            Log.i(TAG, "Free pairing slots: " + info.getFreePairingSlots());

            Boolean isPaired = false;
            Boolean isAuthentic = false;

            if (!pairings.containsKey(instanceUID)) {
                isAuthentic = verifyAuthenticity(cmdSet, instanceUID);
                if (isAuthentic) {
                    isPaired = tryDefaultPairing(cmdSet, instanceUID, cardInfo);
                }
            } else {
                try {
                    openSecureChannel(cmdSet);
                    isPaired = true;
                    isAuthentic = true;
                } catch(APDUException e) {
                    isAuthentic = verifyAuthenticity(cmdSet, instanceUID);
                    if (isAuthentic) {
                        isPaired = tryDefaultPairing(cmdSet, instanceUID, cardInfo);
                    }
                }
            }

            cardInfo.putBoolean("authentic?", isAuthentic);

            if (isPaired) {
                ApplicationStatus status = new ApplicationStatus(cmdSet.getStatus(KeycardCommandSet.GET_STATUS_P1_APPLICATION).checkOK().getData());

                Log.i(TAG, "PIN retry counter: " + status.getPINRetryCount());
                Log.i(TAG, "PUK retry counter: " + status.getPUKRetryCount());

                cardInfo.putInt("pin-retry-counter", status.getPINRetryCount());
                cardInfo.putInt("puk-retry-counter", status.getPUKRetryCount());
            }

            cardInfo.putBoolean("has-master-key?", info.hasMasterKey());
            cardInfo.putBoolean("paired?", isPaired);
            cardInfo.putString("instance-uid", Hex.toHexString(info.getInstanceUID()));
            cardInfo.putString("key-uid", Hex.toHexString(info.getKeyUID()));
            cardInfo.putString("secure-channel-pub-key", Hex.toHexString(info.getSecureChannelPubKey()));
            cardInfo.putString("app-version", info.getAppVersionString());
            cardInfo.putInt("free-pairing-slots", info.getFreePairingSlots());
        }

        return cardInfo;
    }

    public WritableMap factoryResetPost() throws IOException, APDUException {
        ApplicationInfo info = new ApplicationInfo(new KeycardCommandSet(this.cardChannel).select().checkOK().getData());
        Log.i(TAG, "Selecting the factory reset Keycard applet succeeded");

        WritableMap cardInfo = Arguments.createMap();
        cardInfo.putBoolean("initialized?", info.isInitializedCard());

        return cardInfo; 
    }

    public WritableMap factoryResetFallback() throws IOException, APDUException {
        GlobalPlatformCommandSet cmdSet = new GlobalPlatformCommandSet(this.cardChannel);
        cmdSet.select().checkOK();
        Log.i(TAG, "ISD selected");

        cmdSet.openSecureChannel();
        Log.i(TAG, "SecureChannel opened");

        cmdSet.deleteKeycardInstance().checkSW(APDUResponse.SW_OK, APDUResponse.SW_REFERENCED_DATA_NOT_FOUND);
        Log.i(TAG, "Keycard applet instance deleted");

        cmdSet.installKeycardApplet().checkOK();
        Log.i(TAG, "Keycard applet instance re-installed");  

        return factoryResetPost();     
    }

    public WritableMap factoryReset() throws IOException, APDUException {
        KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        APDUResponse resp = cmdSet.select();

        if (!resp.isOK()) {
            return factoryResetFallback();
        }

        ApplicationInfo info = new ApplicationInfo(resp.getData());
        
        if (!info.hasFactoryResetCapability()) {
            return factoryResetFallback();
        }

        if (!cmdSet.factoryReset().isOK()) {
            return factoryResetFallback();
        }

        return factoryResetPost();
    }

    public void deriveKey(final String path, final String pin) throws IOException, APDUException {
        KeycardCommandSet cmdSet = authenticatedCommandSet(pin);

        KeyPath currentPath = new KeyPath(cmdSet.getStatus(KeycardCommandSet.GET_STATUS_P1_KEY_PATH).checkOK().getData());
        Log.i(TAG, "Current key path: " + currentPath);

        if (!currentPath.toString().equals(path)) {
            cmdSet.deriveKey(path).checkOK();
            Log.i(TAG, "Derived " + path);
        }
    }

    public String exportKey(final String pin) throws IOException, APDUException {
        KeycardCommandSet cmdSet = authenticatedCommandSet(pin);

        byte[] key = cmdSet.exportCurrentKey(true).checkOK().getData();

        return Hex.toHexString(key);
    }

    public String exportKeyWithPath(final String pin, final String path) throws IOException, APDUException {
        KeycardCommandSet cmdSet = authenticatedCommandSet(pin);

        byte[] key = BIP32KeyPair.fromTLV(cmdSet.exportKey(path, false, true).checkOK().getData()).getPublicKey();

        return Hex.toHexString(key);
    }

    public WritableMap getKeys(final String pin) throws IOException, APDUException {
        KeycardCommandSet cmdSet = authenticatedCommandSet(pin);

        byte[] tlvWhisper = cmdSet.exportKey(WHISPER_PATH, false, false).checkOK().getData();
        BIP32KeyPair whisperKeyPair = BIP32KeyPair.fromTLV(tlvWhisper);

        byte[] tlvEncryption = cmdSet.exportKey(ENCRYPTION_PATH, false, false).checkOK().getData();
        BIP32KeyPair encryptionKeyPair = BIP32KeyPair.fromTLV(tlvEncryption);

        ApplicationInfo info = cmdSet.getApplicationInfo();

        WritableMap data = Arguments.createMap();
        data.putString("whisper-address", Hex.toHexString(whisperKeyPair.toEthereumAddress()));
        data.putString("whisper-public-key", Hex.toHexString(whisperKeyPair.getPublicKey()));
        data.putString("whisper-private-key", Hex.toHexString(whisperKeyPair.getPrivateKey()));
        data.putString("encryption-public-key", Hex.toHexString(encryptionKeyPair.getPublicKey()));
        data.putString("instance-uid", Hex.toHexString(info.getInstanceUID()));
        data.putString("key-uid", Hex.toHexString(info.getKeyUID()));

        return data;
    }

    public WritableMap importKeys(final String pin) throws IOException, APDUException {
        KeycardCommandSet cmdSet = authenticatedCommandSet(pin);
        ApplicationInfo info = cmdSet.getApplicationInfo();

        byte p2 = (info.getAppVersion() < 0x0310) ? KeycardCommandSet.EXPORT_KEY_P2_PUBLIC_ONLY : KeycardCommandSet.EXPORT_KEY_P2_EXTENDED_PUBLIC;

        byte[] tlvEncryption = cmdSet.exportKey(ENCRYPTION_PATH, false, false).checkOK().getData();
        BIP32KeyPair encryptionKeyPair = BIP32KeyPair.fromTLV(tlvEncryption);

        byte[] tlvMaster = cmdSet.exportKey(MASTER_PATH, false, true).checkOK().getData();
        BIP32KeyPair masterPair = BIP32KeyPair.fromTLV(tlvMaster);

        byte[] tlvRoot = cmdSet.exportKey(ROOT_PATH, false, p2).checkOK().getData();
        BIP32KeyPair rootKeyPair = BIP32KeyPair.fromTLV(tlvRoot);

        byte[] tlvWhisper = cmdSet.exportKey(WHISPER_PATH, false, false).checkOK().getData();
        BIP32KeyPair whisperKeyPair = BIP32KeyPair.fromTLV(tlvWhisper);

        WritableMap data = Arguments.createMap();
        data.putString("address", Hex.toHexString(masterPair.toEthereumAddress()));
        data.putString("public-key", Hex.toHexString(masterPair.getPublicKey()));
        data.putString("wallet-root-address", Hex.toHexString(rootKeyPair.toEthereumAddress()));
        data.putString("wallet-root-public-key", Hex.toHexString(rootKeyPair.getPublicKey()));
        
        if (rootKeyPair.isExtended()) {
            data.putString("wallet-root-chain-code", Hex.toHexString(rootKeyPair.getChainCode()));
        } //else { (for now we return both keys, because xpub support is not yet available)
            byte[] tlvWallet = cmdSet.exportKey(WALLET_PATH, false, true).checkOK().getData();
            BIP32KeyPair walletKeyPair = BIP32KeyPair.fromTLV(tlvWallet);
            data.putString("wallet-address", Hex.toHexString(walletKeyPair.toEthereumAddress()));
            data.putString("wallet-public-key", Hex.toHexString(walletKeyPair.getPublicKey()));
        //}

        data.putString("whisper-address", Hex.toHexString(whisperKeyPair.toEthereumAddress()));
        data.putString("whisper-public-key", Hex.toHexString(whisperKeyPair.getPublicKey()));
        data.putString("whisper-private-key", Hex.toHexString(whisperKeyPair.getPrivateKey()));
        data.putString("encryption-public-key", Hex.toHexString(encryptionKeyPair.getPublicKey()));
        data.putString("instance-uid", Hex.toHexString(info.getInstanceUID()));
        data.putString("key-uid", Hex.toHexString(info.getKeyUID()));

        return data;
    }

    public WritableMap generateAndLoadKey(final String mnemonic, final String pin) throws IOException, APDUException {
        KeycardCommandSet cmdSet = authenticatedCommandSet(pin);
        byte p2 = (cmdSet.getApplicationInfo().getAppVersion() < 0x0310) ? KeycardCommandSet.EXPORT_KEY_P2_PUBLIC_ONLY : KeycardCommandSet.EXPORT_KEY_P2_EXTENDED_PUBLIC;

        byte[] seed = Mnemonic.toBinarySeed(mnemonic, "");
        BIP32KeyPair keyPair = BIP32KeyPair.fromBinarySeed(seed);

        cmdSet.loadKey(keyPair).checkOK();
        log("keypair loaded to card");

        byte[] tlvRoot = cmdSet.exportKey(ROOT_PATH, false, p2).checkOK().getData();
        Log.i(TAG, "Derived " + ROOT_PATH);
        BIP32KeyPair rootKeyPair = BIP32KeyPair.fromTLV(tlvRoot);

        byte[] tlvWhisper = cmdSet.exportKey(WHISPER_PATH, false, false).checkOK().getData();
        Log.i(TAG, "Derived " + WHISPER_PATH);
        BIP32KeyPair whisperKeyPair = BIP32KeyPair.fromTLV(tlvWhisper);

        byte[] tlvEncryption = cmdSet.exportKey(ENCRYPTION_PATH, false, false).checkOK().getData();
        Log.i(TAG, "Derived " + ENCRYPTION_PATH);
        BIP32KeyPair encryptionKeyPair = BIP32KeyPair.fromTLV(tlvEncryption);

        WritableMap data = Arguments.createMap();
        data.putString("address", Hex.toHexString(keyPair.toEthereumAddress()));
        data.putString("public-key", Hex.toHexString(keyPair.getPublicKey()));
        data.putString("wallet-root-address", Hex.toHexString(rootKeyPair.toEthereumAddress()));
        data.putString("wallet-root-public-key", Hex.toHexString(rootKeyPair.getPublicKey()));

        if (rootKeyPair.isExtended()) {
            data.putString("wallet-root-chain-code", Hex.toHexString(rootKeyPair.getChainCode()));
        } //else { (see note above)
            byte[] tlvWallet = cmdSet.exportKey(WALLET_PATH, false, true).checkOK().getData();
            BIP32KeyPair walletKeyPair = BIP32KeyPair.fromTLV(tlvWallet);
            data.putString("wallet-address", Hex.toHexString(walletKeyPair.toEthereumAddress()));
            data.putString("wallet-public-key", Hex.toHexString(walletKeyPair.getPublicKey()));
        //}

        data.putString("whisper-address", Hex.toHexString(whisperKeyPair.toEthereumAddress()));
        data.putString("whisper-public-key", Hex.toHexString(whisperKeyPair.getPublicKey()));
        data.putString("whisper-private-key", Hex.toHexString(whisperKeyPair.getPrivateKey()));
        data.putString("encryption-public-key", Hex.toHexString(encryptionKeyPair.getPublicKey()));

        ApplicationInfo info = new ApplicationInfo(cmdSet.select().checkOK().getData());

        data.putString("instance-uid", Hex.toHexString(info.getInstanceUID()));
        data.putString("key-uid", Hex.toHexString(info.getKeyUID()));

        return data;
    }

    public int verifyPin(final String pin) throws IOException, APDUException {
        KeycardCommandSet cmdSet = authenticatedCommandSet(pin);
        return 3;
    }

    public void changePairingPassword(final String pin, final String pairingPassword) throws IOException, APDUException {
        KeycardCommandSet cmdSet = authenticatedCommandSet(pin);

        cmdSet.changePairingPassword(pairingPassword);
        Log.i(TAG, "pairing password changed");
    }

    public void changePUK(final String pin, final String puk) throws IOException, APDUException {
        KeycardCommandSet cmdSet = authenticatedCommandSet(pin);

        cmdSet.changePUK(puk);
        Log.i(TAG, "puk changed");
    }

    public void changePin(final String currentPin, final String newPin) throws IOException, APDUException {
        KeycardCommandSet cmdSet = authenticatedCommandSet(currentPin);

        cmdSet.changePIN(newPin);
        Log.i(TAG, "pin changed");
    }

    public void unblockPin(final String puk, final String newPin) throws IOException, APDUException {
        KeycardCommandSet cmdSet = securedCommandSet();

        cmdSet.unblockPIN(puk, newPin).checkOK();
        Log.i(TAG, "pin unblocked");
    }

    public void unpair(final String pin) throws IOException, APDUException {
        KeycardCommandSet cmdSet = authenticatedCommandSet(pin);

        cmdSet.autoUnpair();
        Log.i(TAG, "card unpaired");
        String instanceUID = Hex.toHexString(cmdSet.getApplicationInfo().getInstanceUID());
        pairings.remove(instanceUID);
    }

    public void removeKey(final String pin) throws IOException, APDUException {
        KeycardCommandSet cmdSet = authenticatedCommandSet(pin);

        cmdSet.removeKey();
        Log.i(TAG, "key removed");
    }

    public void removeKeyWithUnpair(final String pin) throws IOException, APDUException {
        KeycardCommandSet cmdSet = authenticatedCommandSet(pin);

        cmdSet.removeKey();
        Log.i(TAG, "key removed");

        cmdSet.unpairOthers();
        Log.i(TAG, "unpaired others");

        cmdSet.autoUnpair();
        Log.i(TAG, "card unpaired");

        String instanceUID = Hex.toHexString(cmdSet.getApplicationInfo().getInstanceUID());
        pairings.remove(instanceUID);
    }

    public String sign(final String pin, final String message) throws IOException, APDUException {
        KeycardCommandSet cmdSet = authenticatedCommandSet(pin);

        byte[] hash = Hex.decode(message);
        RecoverableSignature signature = new RecoverableSignature(hash, cmdSet.sign(hash).checkOK().getData());

        Log.i(TAG, "Signed hash: " + Hex.toHexString(hash));
        Log.i(TAG, "Recovery ID: " + signature.getRecId());
        Log.i(TAG, "R: " + Hex.toHexString(signature.getR()));
        Log.i(TAG, "S: " + Hex.toHexString(signature.getS()));

        ByteArrayOutputStream out = new ByteArrayOutputStream();

        out.write(signature.getR());
        out.write(signature.getS());
        out.write(signature.getRecId());

        String sig = Hex.toHexString(out.toByteArray());
        Log.i(TAG, "Signature: " + sig);

        return sig;
    }

    public String signWithPath(final String pin, final String path, final String message) throws IOException, APDUException {
        KeycardCommandSet cmdSet = authenticatedCommandSet(pin);

        byte[] hash = Hex.decode(message);

        RecoverableSignature signature;

        if (cmdSet.getApplicationInfo().getAppVersion() < 0x0202) {
            String actualPath = new KeyPath(cmdSet.getStatus(KeycardCommandSet.GET_STATUS_P1_KEY_PATH).checkOK().getData()).toString();
            if (!actualPath.equals(path)) {
                cmdSet.deriveKey(path).checkOK();
            }
            signature = new RecoverableSignature(hash, cmdSet.sign(hash).checkOK().getData());
        } else {
            signature = new RecoverableSignature(hash, cmdSet.signWithPath(hash, path, false).checkOK().getData());
        }

        Log.i(TAG, "Signed hash: " + Hex.toHexString(hash));
        Log.i(TAG, "Recovery ID: " + signature.getRecId());
        Log.i(TAG, "R: " + Hex.toHexString(signature.getR()));
        Log.i(TAG, "S: " + Hex.toHexString(signature.getS()));

        ByteArrayOutputStream out = new ByteArrayOutputStream();

        out.write(signature.getR());
        out.write(signature.getS());
        out.write(signature.getRecId());

        String sig = Hex.toHexString(out.toByteArray());
        Log.i(TAG, "Signature: " + sig);

        return sig;
    }

    public String signPinless(final String message) throws IOException, APDUException {
        CashCommandSet cmdSet = new CashCommandSet(this.cardChannel);
        cmdSet.select().checkOK();

        byte[] hash = Hex.decode(message);
        RecoverableSignature signature = new RecoverableSignature(hash, cmdSet.sign(hash).checkOK().getData());

        Log.i(TAG, "Signed hash: " + Hex.toHexString(hash));
        Log.i(TAG, "Recovery ID: " + signature.getRecId());
        Log.i(TAG, "R: " + Hex.toHexString(signature.getR()));
        Log.i(TAG, "S: " + Hex.toHexString(signature.getS()));

        ByteArrayOutputStream out = new ByteArrayOutputStream();

        out.write(signature.getR());
        out.write(signature.getS());
        out.write(signature.getRecId());

        String sig = Hex.toHexString(out.toByteArray());
        Log.i(TAG, "Signature: " + sig);

        return sig;
    }

    public String getCardName() throws IOException, APDUException {
        KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        cmdSet.select().checkOK();
        return getCardNameOrDefault(cmdSet);
    } 

    public void setCardName(final String pin, final String name) throws IOException, APDUException {
        KeycardCommandSet cmdSet = authenticatedCommandSet(pin);

        Metadata m = new Metadata(name);
        cmdSet.storeData(m.toByteArray(), KeycardCommandSet.STORE_DATA_P1_PUBLIC).checkOK();
    }    

    public WritableMap verifyCard(final String challenge) throws IOException, APDUException {
        KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        cmdSet.select().checkOK();
        byte[] rawChallenge = Hex.decode(challenge);
        byte[] data = cmdSet.identifyCard(rawChallenge).checkOK().getData();
        byte[] caPubKey = Certificate.verifyIdentity(rawChallenge, data);

        WritableMap out = Arguments.createMap();
        out.putString("ca-public-key", Hex.toHexString(caPubKey));
        out.putString("tlv-data", Hex.toHexString(data));

        return out;
    }

    public void setPairings(ReadableMap newPairings) {
        pairings.clear();
        Iterator<Map.Entry<String,Object>> i = newPairings.getEntryIterator();
        while (i.hasNext()) {
            Map.Entry<String, Object> entry = i.next();
            String value = ((ReadableMap) entry.getValue()).getString("pairing");
            pairings.put(entry.getKey(), value);
        }
    }

    public void setCertificationAuthorities(ReadableArray newCAPubKeys) {
        this.caPubKeys = new String[newCAPubKeys.size()];

        for (int i = 0; i < newCAPubKeys.size(); i++) {
            this.caPubKeys[i] = newCAPubKeys.getString(i);
        }        
    }

    public void setOneTimeVerificationSkip(String instanceUID) {
        this.skipVerificationUID = instanceUID;    
    }

    private KeycardCommandSet authenticatedCommandSet(String pin) throws IOException, APDUException {
        KeycardCommandSet cmdSet = securedCommandSet();
        cmdSet.verifyPIN(pin).checkOK();
        Log.i(TAG, "pin verified");

        return cmdSet;
    }

    private KeycardCommandSet securedCommandSet() throws IOException, APDUException {
        KeycardCommandSet cmdSet = new KeycardCommandSet(this.cardChannel);
        cmdSet.select().checkOK();
        openSecureChannel(cmdSet);

        return cmdSet;
    }

    private String getCardNameOrDefault(KeycardCommandSet cmdSet) throws IOException, APDUException {
        byte[] data = cmdSet.getData(KeycardCommandSet.STORE_DATA_P1_PUBLIC).checkOK().getData();

        try {
            Metadata m = Metadata.fromData(data);
            return m.getCardName();
        } catch(Exception e) {
            return "";
        }
    }

    private void openSecureChannel(KeycardCommandSet cmdSet) throws IOException, APDUException {
        String instanceUID = Hex.toHexString(cmdSet.getApplicationInfo().getInstanceUID());
        String pairingBase64 = pairings.get(instanceUID);

        if (pairingBase64 == null) {
            throw new APDUException("No pairing found");
        }

        Pairing pairing = new Pairing(pairingBase64);
        cmdSet.setPairing(pairing);

        cmdSet.autoOpenSecureChannel();
        Log.i(TAG, "secure channel opened");
    }

}

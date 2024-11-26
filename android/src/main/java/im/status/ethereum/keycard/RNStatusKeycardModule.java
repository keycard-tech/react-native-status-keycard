package im.status.ethereum.keycard;

import android.app.Activity;
import android.content.Intent;
import android.provider.Settings;
import android.util.Log;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.LifecycleEventListener;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.ReadableArray;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import im.status.keycard.io.APDUException;

public class RNStatusKeycardModule extends ReactContextBaseJavaModule implements LifecycleEventListener {
    private static final String TAG = "StatusKeycard";
    private SmartCard smartCard;
    private final ReactApplicationContext reactContext;

    public RNStatusKeycardModule(ReactApplicationContext reactContext) {
        super(reactContext);
        this.reactContext = reactContext;
        reactContext.addLifecycleEventListener(this);
    }

    @Override
    public String getName() {
        return "RNStatusKeycard";
    }

    @Override
    public void onHostResume() {
        if (this.smartCard == null) {
            this.smartCard = new SmartCard(reactContext);
        }

        smartCard.start(getCurrentActivity());
    }

    @Override
    public void onHostPause() {
    }

    @Override
    public void onHostDestroy() {
    }

    // Required for rn built in EventEmitter Calls.
    @ReactMethod
    public void addListener(String eventName) {

    }

    @ReactMethod
    public void removeListeners(Integer count) {

    }    

    @ReactMethod
    public void nfcIsSupported(final Promise promise) {
        if (smartCard != null) {
            promise.resolve(smartCard.isNfcSupported(getCurrentActivity()));
        } else {
            promise.resolve(false);
        }
    }

    @ReactMethod
    public void nfcIsEnabled(final Promise promise) {
        if (smartCard != null) {
            promise.resolve(smartCard.isNfcEnabled());
        } else {
            promise.resolve(false);
        }
    }

    @ReactMethod
    public void openNfcSettings(final Promise promise) {
        Activity currentActivity = getCurrentActivity();
        currentActivity.startActivity(new Intent(Settings.ACTION_NFC_SETTINGS));
        promise.resolve(true);
    }

    @ReactMethod
    public void init(final String pin, final Promise promise) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    SmartCardSecrets s = smartCard.init(pin);

                    WritableMap params = Arguments.createMap();
                    params.putString("pin", s.getPin());
                    params.putString("puk", s.getPuk());
                    params.putString("password", s.getPairingPassword());

                    promise.resolve(params);
                } catch (IOException | APDUException | NoSuchAlgorithmException | InvalidKeySpecException e) {
                    Log.d(TAG, e.getMessage());
                    promise.reject(e);
                }
            }
        }).start();
    }

    @ReactMethod
    public void pair(final String password, final Promise promise) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    String pairing = smartCard.pair(password);
                    Log.d(TAG, "pairing done");

                    promise.resolve(pairing);
                } catch (IOException | APDUException e) {
                    Log.d(TAG, e.getMessage());
                    promise.reject(e);
                }
            }
        }).start();
    }

    @ReactMethod
    public void generateMnemonic(final String words, final Promise promise) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    promise.resolve(smartCard.generateMnemonic(words));
                } catch (IOException | APDUException e) {
                    Log.d(TAG, e.getMessage());
                    promise.reject(e);
                }
            }
        }).start();
    }

    @ReactMethod
    public void generateAndLoadKey(final String mnemonic, final String pin, final Promise promise) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    promise.resolve(smartCard.generateAndLoadKey(mnemonic, pin));
                } catch (IOException | APDUException e) {
                    Log.d(TAG, e.getMessage());
                    promise.reject(e);
                }
            }
        }).start();
    }

    @ReactMethod
    public void saveMnemonic(final String mnemonic, final String pin, final Promise promise) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    smartCard.saveMnemonic(mnemonic, pin);
                    promise.resolve(true);
                } catch (IOException | APDUException e) {
                    Log.d(TAG, e.getMessage());
                    promise.reject(e);
                }
            }
        }).start();
    }

    @ReactMethod
    public void getApplicationInfo(final Promise promise) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    promise.resolve(smartCard.getApplicationInfo());
                } catch (IOException | APDUException e) {
                    Log.d(TAG, e.getMessage());
                    promise.reject(e);
                }
            }
        }).start();
    }

    @ReactMethod
    public void factoryReset(final Promise promise) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    promise.resolve(smartCard.factoryReset());
                } catch (IOException | APDUException e) {
                    Log.d(TAG, e.getMessage());
                    promise.reject(e);
                }
            }
        }).start();
    }

    @ReactMethod
    public void deriveKey(final String path, final String pin, final Promise promise) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    smartCard.deriveKey(path, pin);
                    promise.resolve(path);
                } catch (IOException | APDUException e) {
                    Log.d(TAG, e.getMessage());
                    promise.reject(e);
                }
            }
        }).start();
    }

    @ReactMethod
    public void exportKey(final String pin, final Promise promise) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    promise.resolve(smartCard.exportKey(pin));
                } catch (IOException | APDUException e) {
                    Log.d(TAG, e.getMessage());
                    promise.reject(e);
                }
            }
        }).start();
    }

    @ReactMethod
    public void exportKeyWithPath(final String pin, final String path, final Promise promise) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    promise.resolve(smartCard.exportKeyWithPath(pin, path));
                } catch (IOException | APDUException e) {
                    Log.d(TAG, e.getMessage());
                    promise.reject(e);
                }
            }
        }).start();
    }

    @ReactMethod
    public void getKeys(final String pin, final Promise promise) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    promise.resolve(smartCard.getKeys(pin));
                } catch (IOException | APDUException e) {
                    Log.d(TAG, e.getMessage());
                    promise.reject(e);
                }
            }
        }).start();
    }

    @ReactMethod
    public void importKeys(final String pin, final Promise promise) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    promise.resolve(smartCard.importKeys(pin));
                } catch (IOException | APDUException e) {
                    Log.d(TAG, e.getMessage());
                    promise.reject(e);
                }
            }
        }).start();
    }

    @ReactMethod
    public void sign(final String pin, final String hash, final Promise promise) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    promise.resolve(smartCard.sign(pin, hash));
                } catch (IOException | APDUException e) {
                    Log.d(TAG, e.getMessage());
                    promise.reject(e);
                }
            }
        }).start();
    }

    @ReactMethod
    public void signWithPath(final String pin, final String path, final String hash, final Promise promise) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    promise.resolve(smartCard.signWithPath(pin, path, hash));
                } catch (IOException | APDUException e) {
                    Log.d(TAG, e.getMessage());
                    promise.reject(e);
                }
            }
        }).start();
    }

    @ReactMethod
    public void signPinless(final String hash, final Promise promise) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    promise.resolve(smartCard.signPinless(hash));
                } catch (IOException | APDUException e) {
                    Log.d(TAG, e.getMessage());
                    promise.reject(e);
                }
            }
        }).start();
    }

    @ReactMethod
    public void installApplet(final Promise promise) {
        promise.reject("E_KEYCARD", "Not implemented (unused)");
    }

    @ReactMethod
    public void installAppletAndInitCard(final String pin, final Promise promise) {
        promise.reject("E_KEYCARD", "Not implemented (unused)");
    }

    @ReactMethod
    public void verifyPin(final String pin, final Promise promise) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    promise.resolve(smartCard.verifyPin(pin));
                } catch (IOException | APDUException e) {
                    Log.d(TAG, e.getMessage());
                    promise.reject(e);
                }
            }
        }).start();
    }

    @ReactMethod
    public void changePairingPassword(final String pin, final String pairingPassword, final Promise promise) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    smartCard.changePairingPassword(pin, pairingPassword);
                    promise.resolve(true);
                } catch (IOException | APDUException e) {
                    Log.d(TAG, e.getMessage());
                    promise.reject(e);
                }
            }
        }).start();
    }

    @ReactMethod
    public void changePUK(final String pin, final String puk, final Promise promise) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    smartCard.changePUK(pin, puk);
                    promise.resolve(true);
                } catch (IOException | APDUException e) {
                    Log.d(TAG, e.getMessage());
                    promise.reject(e);
                }
            }
        }).start();
    }

    @ReactMethod
    public void changePin(final String currentPin, final String newPin, final Promise promise) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    smartCard.changePin(currentPin, newPin);
                    promise.resolve(true);
                } catch (IOException | APDUException e) {
                    Log.d(TAG, e.getMessage());
                    promise.reject(e);
                }
            }
        }).start();
    }

    @ReactMethod
    public void unblockPin(final String puk, final String newPin, final Promise promise) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    smartCard.unblockPin(puk, newPin);
                    promise.resolve(true);
                } catch (IOException | APDUException e) {
                    Log.d(TAG, e.getMessage());
                    promise.reject(e);
                }
            }
        }).start();
    }

    @ReactMethod
    public void unpair(final String pin, final Promise promise) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    smartCard.unpair(pin);
                    promise.resolve(true);
                } catch (IOException | APDUException e) {
                    Log.d(TAG, e.getMessage());
                    promise.reject(e);
                }
            }
        }).start();
    }

    @ReactMethod
    public void delete(final Promise promise) {
        promise.reject("E_KEYCARD", "Not implemented (unused)");
    }

    @ReactMethod
    public void removeKey(final String pin, final Promise promise) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    smartCard.removeKey(pin);
                    promise.resolve(true);
                } catch (IOException | APDUException e) {
                    Log.d(TAG, e.getMessage());
                    promise.reject(e);
                }
            }
        }).start();
    }

    @ReactMethod
    public void removeKeyWithUnpair(final String pin, final Promise promise) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    smartCard.removeKeyWithUnpair(pin);
                    promise.resolve(true);
                } catch (IOException | APDUException e) {
                    Log.d(TAG, e.getMessage());
                    promise.reject(e);
                }
            }
        }).start();
    }

    @ReactMethod
    public void getCardName(final Promise promise) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    promise.resolve(smartCard.getCardName());
                } catch (IOException | APDUException e) {
                    Log.d(TAG, e.getMessage());
                    promise.reject(e);
                }
            }
        }).start();
    }

    @ReactMethod
    public void setCardName(final String pin, final String name, final Promise promise) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    smartCard.setCardName(pin, name);
                    promise.resolve(true);
                } catch (IOException | APDUException e) {
                    Log.d(TAG, e.getMessage());
                    promise.reject(e);
                }
            }
        }).start();
    }

    @ReactMethod
    public void unpairAndDelete(final String pin, final Promise promise) {
        promise.reject("E_KEYCARD", "Not implemented (unused)");
    }

    @ReactMethod
    public void verifyCard(final String challenge, final Promise promise) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    promise.resolve(smartCard.verifyCard(challenge));
                } catch (IOException | APDUException e) {
                    Log.d(TAG, e.getMessage());
                    promise.reject(e);
                }
            }
        }).start();
    }

    @ReactMethod
    public void startNFC(String prompt, final Promise promise) {
        smartCard.startNFC();
        promise.resolve(true);
    }

    @ReactMethod
    public void stopNFC(String error, final Promise promise) {
        smartCard.stopNFC();
        promise.resolve(true);
    }

    // Only used on iOS
    @ReactMethod
    public void setNFCMessage(String message, final Promise promise) {
        promise.resolve(true);
    }

    @ReactMethod
    public void setPairings(ReadableMap pairings, final Promise promise) {
        smartCard.setPairings(pairings);
        promise.resolve(true);
    }

    @ReactMethod
    public void setCertificationAuthorities(ReadableArray caPubKeys, final Promise promise) {
        smartCard.setCertificationAuthorities(caPubKeys);
        promise.resolve(true);
    }

    @ReactMethod
    public void setOneTimeVerificationSkip(String instanceUID, final Promise promise) {
        smartCard.setOneTimeVerificationSkip(instanceUID);
        promise.resolve(true);
    }
}

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
            this.smartCard = new SmartCard(getCurrentActivity(), reactContext);
        }
    }

    @Override
    public void onHostPause() {
    }

    @Override
    public void onHostDestroy() {

    }

    @ReactMethod
    public void nfcIsSupported(final Promise promise) {
        if (smartCard != null) {
            promise.resolve(smartCard.isNfcSupported());
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
    public void start(final Promise promise) {
        if (smartCard != null) {
            if (smartCard.start()) {
                promise.resolve(true);
            } else {
                promise.reject("Error", "Not supported on this device");
            }
        } else {
            promise.reject("Error", "smartCard is not initialized yet");
        }
    }

    @ReactMethod
    public void init(final Promise promise) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    SmartCardSecrets s = smartCard.init();

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
    public void generateMnemonic(final String pairing, final Promise promise) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    promise.resolve(smartCard.generateMnemonic(pairing));
                } catch (IOException | APDUException e) {
                    Log.d(TAG, e.getMessage());
                    promise.reject(e);
                }
            }
        }).start();
    }

    @ReactMethod
    public void generateAndLoadKey(final String mnemonic, final String pairing, final String pin, final Promise promise) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    promise.resolve(smartCard.generateAndLoadKey(mnemonic, pairing, pin));
                } catch (IOException | APDUException e) {
                    Log.d(TAG, e.getMessage());
                    promise.reject(e);
                }
            }
        }).start();
    }

    @ReactMethod
    public void saveMnemonic(final String mnemonic, final String pairing, final String pin, final Promise promise) {
        try {
            smartCard.saveMnemonic(mnemonic, pairing, pin);
            promise.resolve(true);
        } catch (IOException | APDUException e) {
            Log.d(TAG, e.getMessage());
            promise.reject(e);
        }
    }

    @ReactMethod
    public void getApplicationInfo(final String pairingBase64, final Promise promise) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    promise.resolve(smartCard.getApplicationInfo(pairingBase64));
                } catch (IOException | APDUException e) {
                    Log.d(TAG, e.getMessage());
                    promise.reject(e);
                }
            }
        }).start();
    }

    @ReactMethod
    public void deriveKey(final String path, final String pairing, final String pin, final Promise promise) {
        try {
            smartCard.deriveKey(path, pairing, pin);
            promise.resolve(path);
        } catch (IOException | APDUException e) {
            Log.d(TAG, e.getMessage());
            promise.reject(e);
        }
    }

    @ReactMethod
    public void exportKey(final String pairing, final String pin, final Promise promise) {
        try {
            promise.resolve(smartCard.exportKey(pairing, pin));
        } catch (IOException | APDUException e) {
            Log.d(TAG, e.getMessage());
            promise.reject(e);
        }
    }

    @ReactMethod
    public void getKeys(final String pairing, final String pin, final Promise promise) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    promise.resolve(smartCard.getKeys(pairing, pin));
                } catch (IOException | APDUException e) {
                    Log.d(TAG, e.getMessage());
                    promise.reject(e);
                }
            }
        }).start();
    }

    @ReactMethod
    public void installApplet(final Promise promise) {
        final ReactContext ctx = this.reactContext;
        new Thread(new Runnable() {
            public void run() {
                try {
                    smartCard.installApplet(ctx.getAssets(), "wallet.cap");
                    promise.resolve(true);
                } catch (IOException | APDUException | NoSuchAlgorithmException | InvalidKeySpecException e) {
                    Log.d(TAG, e.getMessage());
                    promise.reject(e);
                }
            }
        }).start();
    }

    @ReactMethod
    public void installAppletAndInitCard(final Promise promise) {
        final ReactContext ctx = this.reactContext;
        new Thread(new Runnable() {
            public void run() {
                try {
                    SmartCardSecrets s = smartCard.installAppletAndInitCard(ctx.getAssets(), "wallet.cap");

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
    public void verifyPin(final String pairing, final String pin, final Promise promise) {
        try {
            promise.resolve(smartCard.verifyPin(pairing, pin));
        } catch (IOException | APDUException e) {
            Log.d(TAG, e.getMessage());
            promise.reject(e);
        }
    }

    @ReactMethod
    public void changePin(final String pairing, final String currentPin, final String newPin, final Promise promise) {
        try {
            smartCard.changePin(pairing, currentPin, newPin);
            promise.resolve(true);
        } catch (IOException | APDUException e) {
            Log.d(TAG, e.getMessage());
            promise.reject(e);
        }
    }

    @ReactMethod
    public void unblockPin(final String pairing, final String puk, final String newPin, final Promise promise) {
        try {
            smartCard.unblockPin(pairing, puk, newPin);
            promise.resolve(true);
        } catch (IOException | APDUException e) {
            Log.d(TAG, e.getMessage());
            promise.reject(e);
        }
    }

    @ReactMethod
    public void unpair(final String pairing, final String pin, final Promise promise) {
        try {
            smartCard.unpair(pairing, pin);
            promise.resolve(true);
        } catch (IOException | APDUException e) {
            Log.d(TAG, e.getMessage());
            promise.reject(e);
        }
    }

    @ReactMethod
    public void delete(final Promise promise) {
        try {
            smartCard.delete();
            promise.resolve(true);
        } catch (IOException | APDUException e) {
            Log.d(TAG, e.getMessage());
            promise.reject(e);
        }
    }

    @ReactMethod
    public void unpairAndDelete(final String pairing, final String pin, final Promise promise) {
        try {
            smartCard.unpairAndDelete(pairing, pin);
            promise.resolve(true);
        } catch (IOException | APDUException e) {
            Log.d(TAG, e.getMessage());
            promise.reject(e);
        }
    }

}
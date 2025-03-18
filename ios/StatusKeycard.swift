import Foundation
import Keycard
import UIKit
import os.log

@objc(StatusKeycard)
class StatusKeycard: RCTEventEmitter {
    let smartCard = SmartCard()
    var cardChannel: CardChannel? = nil
    var nfcStartPrompt: String = "Hold your iPhone close to a Keycard"

    private var _keycardController: Any? = nil
    
    @available(iOS 13.0, *)
    private var keycardController: KeycardController? {
      get {
        return _keycardController as? KeycardController
      }

      set(kc) {
        _keycardController = kc
      }
    }

    @objc
    func nfcIsSupported(_ resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void {
      if #available(iOS 13.0, *) {
        resolve(KeycardController.isAvailable)
      } else {
        resolve(false)
      }
    }

    @objc
    func nfcIsEnabled(_ resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void {
      // On iOS NFC is always enabled (if available)
      nfcIsSupported(resolve, reject: reject)
    }

    @objc
    func openNfcSettings(_ resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void {
      // NFC cannot be enabled/disabled
      reject("E_KEYCARD", "Unsupported on iOS", nil)
    }

    @objc
    func `init`(_ pin: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.initialize(channel: channel, pin: pin, resolve: resolve, reject: reject) }
    }

    @objc
    func pair(_ pairingPassword: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.pair(channel: channel, pairingPassword: pairingPassword, resolve: resolve, reject: reject) }
    }

    @objc
    func generateMnemonic(_ words: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.generateMnemonic(channel: channel, words: words, resolve: resolve, reject: reject) }
    }

    @objc
    func generateAndLoadKey(_ mnemonic: String, pin: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.generateAndLoadKey(channel: channel, mnemonic: mnemonic, pin: pin, resolve: resolve, reject: reject) }
    }

    @objc
    func saveMnemonic(_ mnemonic: String, pin: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.saveMnemonic(channel: channel, mnemonic: mnemonic, pin: pin, resolve: resolve, reject: reject) }
    }

    @objc
    func factoryReset(_ resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.factoryReset(channel: channel, resolve: resolve, reject: reject) }
    }
    
    @objc
    func verifyCard(_ challenge: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.verifyCard(channel: channel, challenge: challenge, resolve: resolve, reject: reject) }
    }

    @objc
    func getApplicationInfo(_ resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.getApplicationInfo(channel: channel, eventEmitter: self, resolve: resolve, reject: reject) }
    }

    @objc
    func deriveKey(_ path: String, pin: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.deriveKey(channel: channel, path: path, pin: pin, resolve: resolve, reject: reject) }
    }

    @objc
    func exportKey(_ pin: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.exportKey(channel: channel, pin: pin, resolve: resolve, reject: reject) }
    }

    @objc
    func exportKeyWithPath(_ pin: String, path: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.exportKeyWithPath(channel: channel, pin: pin, path: path, resolve: resolve, reject: reject) }
    }

    @objc
    func importKeys(_ pin: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.importKeys(channel: channel, pin: pin, resolve: resolve, reject: reject) }
    }

    @objc
    func getKeys(_ pin: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.getKeys(channel: channel, pin: pin, resolve: resolve, reject: reject) }
    }

    @objc
    func sign(_ pin: String, hash: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.sign(channel: channel, pin: pin, message: hash, resolve: resolve, reject: reject) }
    }

    @objc
    func signWithPath(_ pin: String, path: String, hash: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.signWithPath(channel: channel, pin: pin, path: path, message: hash, resolve: resolve, reject: reject) }
    }

    @objc
    func signPinless(_ hash: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.signPinless(channel: channel, message: hash, resolve: resolve, reject: reject) }
    }

    @objc
    func installApplet(_ resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      reject("E_KEYCARD", "Not implemented (unused)", nil)
    }

    @objc
    func installAppletAndInitCard(_ pin: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      reject("E_KEYCARD", "Not implemented (unused)", nil)
    }

    @objc
    func verifyPin(_ pin: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.verifyPin(channel: channel, pin: pin, resolve: resolve, reject: reject) }
    }

    @objc
    func changePairingPassword(_ pin: String, pairingPassword: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.changePairingPassword(channel: channel, pin: pin, pairingPassword: pairingPassword, resolve: resolve, reject: reject) }
    }

    @objc
    func changePUK(_ pin: String, puk: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.changePUK(channel: channel, pin: pin, puk: puk, resolve: resolve, reject: reject) }
    }

    @objc
    func changePin(_ currentPin: String, newPin: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.changePin(channel: channel, currentPin: currentPin, newPin: newPin, resolve: resolve, reject: reject) }
    }

    @objc
    func unblockPin(_ puk: String, newPin: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.unblockPin(channel: channel, puk: puk, newPin: newPin, resolve: resolve, reject: reject) }
    }

    @objc
    func unpair(_ pin: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.unpair(channel: channel, pin: pin, resolve: resolve, reject: reject) }
    }

    @objc
    func delete(_ resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      reject("E_KEYCARD", "Not implemented (unused)", nil)
    }

    @objc
    func removeKey(_ pin: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.removeKey(channel: channel, pin: pin, resolve: resolve, reject: reject) }
    }

    @objc
    func removeKeyWithUnpair(_ pin: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.removeKeyWithUnpair(channel: channel, pin: pin, resolve: resolve, reject: reject) }
    }

    @objc
    func getCardName(_ resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.getCardName(channel: channel, resolve: resolve, reject: reject) }
    }
    
    @objc
    func setCardName(_ pin: String, name: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      keycardInvokation(reject) { [unowned self] channel in try self.smartCard.setCardName(channel: channel, pin: pin, name: name, resolve: resolve, reject: reject) }
    }

    @objc
    func unpairAndDelete(_ pin: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      reject("E_KEYCARD", "Not implemented (unused)", nil)
    }

    @objc
    func setPairings(_ pairings: NSDictionary, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      self.smartCard.setPairings(newPairings: pairings, resolve: resolve, reject: reject)
    }

    @objc
    func setCertificationAuthorities(_ caPubKeys: NSArray, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      self.smartCard.setCertificationAuthorities(newCAPubKeys: caPubKeys, resolve: resolve, reject: reject)
    }

    @objc
    func setOneTimeVerificationSkip(_ instanceUID: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
      self.smartCard.setOneTimeVerificationSkip(instanceUID: instanceUID, resolve: resolve, reject: reject)
    }

    @objc
    func startNFC(_ prompt: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void {
      if #available(iOS 13.0, *) {
        if (keycardController == nil) {
          self.keycardController = KeycardController(onConnect: { [unowned self] channel in
            self.cardChannel = channel

            let feedbackGenerator = UINotificationFeedbackGenerator()
            feedbackGenerator.prepare()

            DispatchQueue.main.async {
              feedbackGenerator.notificationOccurred(.success)
            }
            self.sendEvent(withName: "keyCardOnConnected", body: nil)
            self.keycardController?.setAlert("Connected. Don't move your card.")
            os_log("[react-native-status-keycard] card connected")
          }, onFailure: { [unowned self] error in
            self.cardChannel = nil
            self.keycardController = nil

            os_log("[react-native-status-keycard] NFCError: %@", String(describing: error))

            if type(of: error) is NSError.Type {
              let nsError = error as NSError
              if nsError.code == 200 && nsError.domain == "NFCError" {
                self.sendEvent(withName: "keyCardOnNFCUserCancelled", body: nil)
              } else if (nsError.code == 201 || nsError.code == 203) && (nsError.domain == "NFCError") {
                self.sendEvent(withName: "keyCardOnNFCTimeout", body: nil)
              }
            }
          })

          self.nfcStartPrompt = prompt.isEmpty ? nfcStartPrompt : prompt
          keycardController?.start(alertMessage: self.nfcStartPrompt)
          resolve(true)
        } else {
          reject("E_KEYCARD", "already started", nil)
        }
      } else {
        reject("E_KEYCARD", "unavailable", nil)
      }
    }

    @objc
    func stopNFC(_ err: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void {
      if #available(iOS 13.0, *) {
        if (err.isEmpty) {
          self.keycardController?.stop(alertMessage: "Success")
        } else {
          self.keycardController?.stop(errorMessage: err)
        }
        self.cardChannel = nil
        self.keycardController = nil
        resolve(true)
      } else {
        reject("E_KEYCARD", "unavailable", nil)
      }
    }

    @objc
    func setNFCMessage(_ message: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void {
      if #available(iOS 13.0, *) {
        self.keycardController?.setAlert(message)
        resolve(true)
      } else {
        reject("E_KEYCARD", "unavailable", nil)
      }
    }

    override static func requiresMainQueueSetup() -> Bool {
      return true
    }

    override func supportedEvents() -> [String]! {
      return ["keyCardOnConnected", "keyCardOnDisconnected", "keyCardOnNFCEnabled", "keyCardOnNFCDisabled", "keyCardOnNFCTimeout", "keyCardOnNFCUserCancelled"]
    }

    func keycardInvokation(_ reject: @escaping RCTPromiseRejectBlock, body: @escaping (CardChannel) throws -> Void) {
      if #available(iOS 13.0, *) {
        if self.cardChannel != nil {
          DispatchQueue.global().async { [unowned self] in
            do {
              try body(self.cardChannel!)
            } catch {
              var errMsg = ""

              if type(of: error) is NSError.Type {
                let nsError = error as NSError
                errMsg = "\(nsError.domain):\(nsError.code)"
                if (nsError.code == 100 || nsError.code == 102) && nsError.domain == "NFCError" {
                  self.sendEvent(withName: "keyCardOnDisconnected", body: nil)
                  self.keycardController?.restartPolling()
                  self.keycardController?.setAlert(self.nfcStartPrompt)
                }
              } else {
                errMsg = "\(error)"
              }
              reject("E_KEYCARD", errMsg, error)
            }
          }
        } else {
          reject("E_KEYCARD", "not connected", nil)
        }
      } else {
        reject("E_KEYCARD", "unavailable", nil)
      }
    }
}

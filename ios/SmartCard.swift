import Foundation
import Keycard
import os.log

enum SmartCardError: Error {
    case invalidBase64
    case noPairing
}

enum DerivationPath: String {
  case masterPath = "m"
  case rootPath = "m/44'/60'/0'/0"
  case walletPath = "m/44'/60'/0'/0/0"
  case whisperPath = "m/43'/60'/1581'/0'/0"
  case encryptionPath = "m/43'/60'/1581'/1'/0"
}

class SmartCard {
    var pairings: [String: String] = [:]
    var caPubKeys: [String] = []
    var skipVerificationUID: String = ""

    func initialize(channel: CardChannel, pin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let puk = self.randomPUK()
      let pairingPassword = "KeycardDefaultPairing"

      let cmdSet = KeycardCommandSet(cardChannel: channel)
      try cmdSet.select().checkOK()
      try cmdSet.initialize(pin: pin, puk: puk, pairingPassword: pairingPassword).checkOK()

      resolve(["pin": pin, "puk": puk, "password": pairingPassword])
    }

    func pair(channel: CardChannel, pairingPassword: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = KeycardCommandSet(cardChannel: channel)
      let info = try ApplicationInfo(cmdSet.select().checkOK().data)

      logAppInfo(info)

      try cmdSet.autoPair(password: pairingPassword)
      let pairing = Data(cmdSet.pairing!.bytes).base64EncodedString()
      self.pairings[bytesToHex(info.instanceUID)] = pairing
      resolve(pairing)
    }

    func generateMnemonic(channel: CardChannel, words: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = try securedCommandSet(channel: channel)

      let mnemonic = try Mnemonic(rawData: cmdSet.generateMnemonic(length: GenerateMnemonicP1.length12Words).checkOK().data)
      mnemonic.wordList = words.components(separatedBy: .newlines)

      resolve(mnemonic.toMnemonicPhrase())
    }

    func generateAndLoadKey(channel: CardChannel, mnemonic: String, pin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = try authenticatedCommandSet(channel: channel, pin: pin)
      let exportOption = cmdSet.info!.appVersion < 0x0310 ? KeycardCommandSet.ExportOption.publicOnly : .extendedPublic
        
      let seed = Mnemonic.toBinarySeed(mnemonicPhrase: mnemonic)
      let keyPair = BIP32KeyPair(fromSeed: seed)

      try cmdSet.loadKey(keyPair: keyPair).checkOK()
      os_log("keypair loaded to card")

      let rootKeyPair = try exportKey(cmdSet: cmdSet, path: .rootPath, makeCurrent: false, exportOption: exportOption)
      let whisperKeyPair = try exportKey(cmdSet: cmdSet, path: .whisperPath, makeCurrent: false, publicOnly: false)
      let encryptionKeyPair = try exportKey(cmdSet: cmdSet, path: .encryptionPath, makeCurrent: false, publicOnly: false)

      var keys = [
        "address": bytesToHex(keyPair.toEthereumAddress()),
        "public-key": bytesToHex(keyPair.publicKey),
        "wallet-root-address": bytesToHex(rootKeyPair.toEthereumAddress()),
        "wallet-root-public-key": bytesToHex(rootKeyPair.publicKey),
        "whisper-address": bytesToHex(whisperKeyPair.toEthereumAddress()),
        "whisper-public-key": bytesToHex(whisperKeyPair.publicKey),
        "whisper-private-key": bytesToHex(whisperKeyPair.privateKey!),
        "encryption-public-key": bytesToHex(encryptionKeyPair.publicKey)
      ]
        
      if rootKeyPair.isExtended {
        keys["wallet-root-chain-code"] = bytesToHex(rootKeyPair.chainCode!)
      } //else { (for now we return both keys, because xpub support is not yet available)
        let walletKeyPair = try exportKey(cmdSet: cmdSet, path: .walletPath, makeCurrent: false, publicOnly: true)
        keys["wallet-address"] = bytesToHex(walletKeyPair.toEthereumAddress())
        keys["wallet-public-key"] = bytesToHex(walletKeyPair.publicKey)
      //}
        
      let info = try ApplicationInfo(cmdSet.select().checkOK().data)
      keys["instance-uid"] = bytesToHex(info.instanceUID)
      keys["key-uid"] = bytesToHex(info.keyUID)
    
      resolve(keys)
    }

    func saveMnemonic(channel: CardChannel, mnemonic: String, pin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = try authenticatedCommandSet(channel: channel, pin: pin)
      let seed = Mnemonic.toBinarySeed(mnemonicPhrase: mnemonic)
      try cmdSet.loadKey(seed: seed).checkOK()
      os_log("seed loaded to card")
      resolve(true)
    }

    func factoryResetPost(channel: CardChannel, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let info = try ApplicationInfo(KeycardCommandSet(cardChannel: channel).select().checkOK().data)
      os_log("Selecting the factory reset Keycard applet succeeded")

      var cardInfo = [String: Any]()
      cardInfo["initialized?"] = info.initializedCard

      resolve(cardInfo)
    }

    func factoryResetFallback(channel: CardChannel, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet: GlobalPlatformCommandSet = GlobalPlatformCommandSet(cardChannel: channel)
      try cmdSet.select().checkOK()
      os_log("ISD selected")

      try cmdSet.openSecureChannel()
      os_log("SecureChannel opened")

      try cmdSet.deleteKeycardInstance().checkSW(StatusWord.ok, StatusWord.referencedDataNotFound)
      os_log("Keycard applet instance deleted")

      try cmdSet.installKeycardInstance().checkOK()
      os_log("Keycard applet instance re-installed")

      try factoryResetPost(channel: channel, resolve: resolve, reject: reject)
    }

    func factoryReset(channel: CardChannel, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = KeycardCommandSet(cardChannel: channel)
      var resp = try cmdSet.select()
      
      if (resp.sw != 0x9000) {
        try factoryResetFallback(channel: channel, resolve: resolve, reject: reject)
        return
      }

      let info = try ApplicationInfo(resp.data)
      if (!info.hasFactoryResetCapability) {
        try factoryResetFallback(channel: channel, resolve: resolve, reject: reject)
        return
      }

      resp = try cmdSet.factoryReset()

      if (resp.sw != 0x9000) {
        try factoryResetFallback(channel: channel, resolve: resolve, reject: reject)
        return
      }

      try factoryResetPost(channel: channel, resolve: resolve, reject: reject)
    }
    
    func verifyCard(channel: CardChannel, challenge: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws {
      let cmdSet = KeycardCommandSet(cardChannel: channel)
      try cmdSet.select().checkOK()
      let rawChallenge = hexToBytes(challenge)
      let data = try cmdSet.identifyCard(challenge: rawChallenge).checkOK().data
      let caPubKey = try Certificate.verifyIdentity(hash: rawChallenge, tlvData: data)

      resolve([
        "ca-public-key": bytesToHex(caPubKey ?? []),
        "tlv-data": bytesToHex(data)
      ])
    }

    private func verifyAuthenticity(cmdSet: KeycardCommandSet, instanceUID: String) throws -> Bool {
      if (self.caPubKeys.count == 0 || self.skipVerificationUID == instanceUID) {
        self.skipVerificationUID = ""
        return true
      }

      let rawChallenge = (0..<32).map({ _ in UInt8.random(in: 0...UInt8.max) })
      
      do {
        let data = try cmdSet.identifyCard(challenge: rawChallenge).checkOK().data
        let caPubKey = try Certificate.verifyIdentity(hash: rawChallenge, tlvData: data)

        if let caPubKeyBytes = caPubKey {
          return self.caPubKeys.contains(bytesToHex(caPubKeyBytes))
        }
      } catch _ as StatusWord {}

      return false
    }

    func getApplicationInfo(channel: CardChannel, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = KeycardCommandSet(cardChannel: channel)
      let info = try ApplicationInfo(cmdSet.select().checkOK().data)

      os_log("Card initialized? %@", String(info.initializedCard))
      var cardInfo = [String: Any]()
      cardInfo["initialized?"] = info.initializedCard

      if (info.initializedCard) {
        logAppInfo(info)
        let cardName = try cardNameOrDefault(cmdSet: cmdSet)
        cardInfo["card-name"] = cardName
        
        var isPaired = false
        var isAuthentic = false
        let instanceUID = bytesToHex(info.instanceUID)

        if let _ = self.pairings[instanceUID] {
          do {
            try openSecureChannel(cmdSet: cmdSet)
            isPaired = true
            isAuthentic = true
          } catch _ as CardError {
            isPaired = false
          } catch _ as StatusWord {
            isPaired = false
          }
        } 
        
        if (!isPaired) {
          isAuthentic = try verifyAuthenticity(cmdSet: cmdSet, instanceUID: instanceUID)

          if (isAuthentic) {
            isPaired = try tryDefaultPairing(cmdSet: cmdSet, cardInfo: &cardInfo)
          }
        }

        cardInfo["authentic?"] = isAuthentic

        if (isPaired) {
          let status = try ApplicationStatus(cmdSet.getStatus(info: GetStatusP1.application.rawValue).checkOK().data)
          os_log("PIN retry counter: %d", status.pinRetryCount)
          os_log("PUK retry counter: %d", status.pukRetryCount)

          cardInfo["pin-retry-counter"] = status.pinRetryCount
          cardInfo["puk-retry-counter"] = status.pukRetryCount
        }

        cardInfo["paired?"] = isPaired
      }

      cardInfo["has-master-key?"] = info.hasMasterKey
      cardInfo["instance-uid"] = bytesToHex(info.instanceUID)
      cardInfo["key-uid"] = bytesToHex(info.keyUID)
      cardInfo["secure-channel-pub-key"] = bytesToHex(info.secureChannelPubKey)
      cardInfo["app-version"] = info.appVersionString
      cardInfo["free-pairing-slots"] = info.freePairingSlots

      resolve(cardInfo)
    }

    func deriveKey(channel: CardChannel, path: String, pin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = try authenticatedCommandSet(channel: channel, pin: pin)
      let currentPath = try KeyPath(data: cmdSet.getStatus(info: GetStatusP1.keyPath.rawValue).checkOK().data)
      os_log("Current key path: %@", currentPath.description)

      if (currentPath.description != path) {
        try cmdSet.deriveKey(path: path).checkOK()
        os_log("Derived %@", path)
      }

      resolve(true)
    }

    func exportKey(channel: CardChannel, pin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = try authenticatedCommandSet(channel: channel, pin: pin)
      let key = try cmdSet.exportCurrentKey(publicOnly: true).checkOK().data
      resolve(bytesToHex(key))
    }

    func exportKeyWithPath(channel: CardChannel, pin: String, path: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = try authenticatedCommandSet(channel: channel, pin: pin)
      let key = try BIP32KeyPair(fromTLV: cmdSet.exportKey(path: path, makeCurrent: false, publicOnly: true).checkOK().data).publicKey

      resolve(bytesToHex(key))
    }

    func importKeys(channel: CardChannel, pin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = try authenticatedCommandSet(channel: channel, pin: pin)
      let info = cmdSet.info!
      let exportOption = info.appVersion < 0x0310 ? KeycardCommandSet.ExportOption.publicOnly : .extendedPublic

      let encryptionKeyPair = try exportKey(cmdSet: cmdSet, path: .encryptionPath, makeCurrent: false, publicOnly: false)
      let masterPair = try exportKey(cmdSet: cmdSet, path: .masterPath, makeCurrent: false, publicOnly: true)
      let rootKeyPair = try exportKey(cmdSet: cmdSet, path: .rootPath, makeCurrent: false, exportOption: exportOption)
      let whisperKeyPair = try exportKey(cmdSet: cmdSet, path: .whisperPath, makeCurrent: false, publicOnly: false)

      var keys = [
        "address": bytesToHex(masterPair.toEthereumAddress()),
        "public-key": bytesToHex(masterPair.publicKey),
        "wallet-root-address": bytesToHex(rootKeyPair.toEthereumAddress()),
        "wallet-root-public-key": bytesToHex(rootKeyPair.publicKey),
        "whisper-address": bytesToHex(whisperKeyPair.toEthereumAddress()),
        "whisper-public-key": bytesToHex(whisperKeyPair.publicKey),
        "whisper-private-key": bytesToHex(whisperKeyPair.privateKey!),
        "encryption-public-key": bytesToHex(encryptionKeyPair.publicKey),
        "instance-uid": bytesToHex(info.instanceUID),
        "key-uid": bytesToHex(info.keyUID)
      ]
        
      if rootKeyPair.isExtended {
        keys["wallet-root-chain-code"] = bytesToHex(rootKeyPair.chainCode!)
      } //else { (see note above)
        let walletKeyPair = try exportKey(cmdSet: cmdSet, path: .walletPath, makeCurrent: false, publicOnly: true)
        keys["wallet-address"] = bytesToHex(walletKeyPair.toEthereumAddress())
        keys["wallet-public-key"] = bytesToHex(walletKeyPair.publicKey)
      //}
        
      resolve(keys)
    }

    func getKeys(channel: CardChannel, pin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = try authenticatedCommandSet(channel: channel, pin: pin)

      let whisperKeyPair = try exportKey(cmdSet: cmdSet, path: .whisperPath, makeCurrent: false, publicOnly: false)
      let encryptionKeyPair = try exportKey(cmdSet: cmdSet, path: .encryptionPath, makeCurrent: false, publicOnly: false)

      let info = cmdSet.info!

      resolve([
        "whisper-address": bytesToHex(whisperKeyPair.toEthereumAddress()),
        "whisper-public-key": bytesToHex(whisperKeyPair.publicKey),
        "whisper-private-key": bytesToHex(whisperKeyPair.privateKey!),
        "encryption-public-key": bytesToHex(encryptionKeyPair.publicKey),
        "instance-uid": bytesToHex(info.instanceUID),
        "key-uid": bytesToHex(info.keyUID)
      ])
    }

    func sign(channel: CardChannel, pin: String, message: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = try authenticatedCommandSet(channel: channel, pin: pin)
      let sig = try processSignature(message) { return try cmdSet.sign(hash: $0) }
      resolve(sig)
    }

    func signWithPath(channel: CardChannel, pin: String, path: String, message: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = try authenticatedCommandSet(channel: channel, pin: pin)
      let sig = try processSignature(message) {
        if (cmdSet.info!.appVersion < 0x0202) {
          let currentPath = try KeyPath(data: cmdSet.getStatus(info: GetStatusP1.keyPath.rawValue).checkOK().data)

          if (currentPath.description != path) {
            try cmdSet.deriveKey(path: path).checkOK()
          }

          return try cmdSet.sign(hash: $0)
        } else {
          return try cmdSet.sign(hash: $0, path: path, makeCurrent: false)
        }
      }

      resolve(sig)
    }

    func signPinless(channel: CardChannel, message: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = CashCommandSet(cardChannel: channel)
      try cmdSet.select().checkOK()

      let sig = try processSignature(message) { return try cmdSet.sign(data: $0) }
      resolve(sig)
    }

    func verifyPin(channel: CardChannel, pin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let _ = try authenticatedCommandSet(channel: channel, pin: pin)
      resolve(3)
    }

    func changePairingPassword(channel: CardChannel, pin: String, pairingPassword: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = try authenticatedCommandSet(channel: channel, pin: pin)
      try cmdSet.changePairingPassword(pairingPassword: pairingPassword).checkOK()
      os_log("pairing password changed")
      resolve(true)
    }

    func changePUK(channel: CardChannel, pin: String, puk: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = try authenticatedCommandSet(channel: channel, pin: pin)
      try cmdSet.changePUK(puk: puk).checkOK()
      os_log("puk changed")
      resolve(true)
    }

    func changePin(channel: CardChannel, currentPin: String, newPin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = try authenticatedCommandSet(channel: channel, pin: currentPin)
      try cmdSet.changePIN(pin: newPin).checkOK()
      os_log("pin changed")
      resolve(true)
    }

    func unblockPin(channel: CardChannel, puk: String, newPin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = try securedCommandSet(channel: channel)
      try cmdSet.unblockPIN(puk: puk, newPIN: newPin).checkAuthOK()
      os_log("pin unblocked")
      resolve(true)
    }

    func unpair(channel: CardChannel, pin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = try authenticatedCommandSet(channel: channel, pin: pin)

      try cmdSet.autoUnpair()
      os_log("card unpaired")

      self.pairings[bytesToHex(cmdSet.info!.instanceUID)] = nil
      resolve(true)
    }

    func removeKey(channel: CardChannel, pin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = try authenticatedCommandSet(channel: channel, pin: pin)
      try cmdSet.removeKey().checkOK()
      os_log("key removed")

      resolve(true)
    }

    func removeKeyWithUnpair(channel: CardChannel, pin: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = try authenticatedCommandSet(channel: channel, pin: pin)
      try cmdSet.removeKey().checkOK()
      os_log("key removed")

      try cmdSet.unpairOthers()
      os_log("unpaired others")

      try cmdSet.autoUnpair()
      os_log("card unpaired")

      self.pairings[bytesToHex(cmdSet.info!.instanceUID)] = nil

      resolve(true)
    }
    
    func getCardName(channel: CardChannel, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = KeycardCommandSet(cardChannel: channel)
      try cmdSet.select().checkOK()
      resolve(try cardNameOrDefault(cmdSet: cmdSet))
    }
    
    func setCardName(channel: CardChannel, pin: String, name: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) throws -> Void {
      let cmdSet = try authenticatedCommandSet(channel: channel, pin: pin)
      let m = Metadata(name)
      try cmdSet.storeData(data: m.serialize(), type: Keycard.StoreDataP1.publicData.rawValue).checkOK()
      resolve(true)
    }

    func randomPUK() -> String {
      return String(format: "%012ld", Int64.random(in: 0..<999999999999))
    }

    func randomPairingPassword() -> String {
      let digits = "23456789"
      let letters = "abcdefghijkmnopqrstuvwxyz"
      return String((0..<5).map{ i in ((i % 2) == 0) ? letters.randomElement()! : digits.randomElement()! })
    }

    func exportKey(cmdSet: KeycardCommandSet, path: DerivationPath, makeCurrent: Bool, publicOnly: Bool) throws -> BIP32KeyPair {
      let option = publicOnly ? KeycardCommandSet.ExportOption.publicOnly : KeycardCommandSet.ExportOption.privateAndPublic
      return try exportKey(cmdSet: cmdSet, path: path, makeCurrent: makeCurrent, exportOption: option)
    }
    
    func exportKey(cmdSet: KeycardCommandSet, path: DerivationPath, makeCurrent: Bool, exportOption: KeycardCommandSet.ExportOption) throws -> BIP32KeyPair {
      let tlvRoot = try cmdSet.exportKey(path: path.rawValue, makeCurrent: makeCurrent, exportOption: exportOption).checkOK().data
      os_log("Derived %@", path.rawValue)
      return try BIP32KeyPair(fromTLV: tlvRoot)
    }
    
    func cardNameOrDefault(cmdSet: KeycardCommandSet) throws -> String {
      let data = try cmdSet.getData(type: Keycard.StoreDataP1.publicData.rawValue).checkOK().data
      
      if data.count > 0 {
        do {
          return try Metadata.fromData(data).cardName
        } catch _ {}
      }
      
      return ""
    }

    func setPairings(newPairings: NSDictionary, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void {
      self.pairings.removeAll()
      for case let (instanceUID as String, v as NSDictionary) in newPairings {
        self.pairings[instanceUID] = v["pairing"] as? String
      }

      resolve(true)
    }

    func setCertificationAuthorities(newCAPubKeys: NSArray, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void {
      self.caPubKeys.removeAll()
      for caPubKey in (newCAPubKeys as! [String]) {
        self.caPubKeys.append(caPubKey)
      }

      resolve(true)
    }

    func setOneTimeVerificationSkip(instanceUID: String, resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void {
      self.skipVerificationUID = instanceUID
      resolve(true)
    }

    func authenticatedCommandSet(channel: CardChannel, pin: String) throws -> KeycardCommandSet {
      let cmdSet = try securedCommandSet(channel: channel)
      try cmdSet.verifyPIN(pin: pin).checkAuthOK()
      os_log("pin verified")

      return cmdSet
    }

    func securedCommandSet(channel: CardChannel) throws -> KeycardCommandSet {
      let cmdSet = KeycardCommandSet(cardChannel: channel)
      try cmdSet.select().checkOK()
      try openSecureChannel(cmdSet: cmdSet)

      return cmdSet
    }

    func tryDefaultPairing(cmdSet: KeycardCommandSet, cardInfo: inout [String: Any]) throws -> Bool {
      do {
        try cmdSet.autoPair(password: "KeycardDefaultPairing")
        let pairing = Data(cmdSet.pairing!.bytes).base64EncodedString()
        self.pairings[bytesToHex(cmdSet.info!.instanceUID)] = pairing
        cardInfo["new-pairing"] = pairing

        try openSecureChannel(cmdSet: cmdSet)
        return true
      } catch let error as CardError {
        os_log("autoOpenSecureChannel failed: %@", String(describing: error))
      } catch let error as StatusWord {
        os_log("autoOpenSecureChannel failed: %@", String(describing: error))
      }

      return false
    }

    func openSecureChannel(cmdSet: KeycardCommandSet) throws -> Void {
      if let pairingBase64 = self.pairings[bytesToHex(cmdSet.info!.instanceUID)] {
        cmdSet.pairing = try base64ToPairing(pairingBase64)

        try cmdSet.autoOpenSecureChannel()
        os_log("secure channel opened")
      } else {
        throw SmartCardError.noPairing
      }
    }

    func processSignature(_ message: String, sign: ([UInt8]) throws -> APDUResponse) throws -> String {
      let hash = hexToBytes(message)
      let signature = try RecoverableSignature(hash: hash, data: sign(hash).checkOK().data)
      logSignature(hash, signature)
      return formatSignature(signature)
    }

    func base64ToPairing(_ base64: String) throws -> Pairing {
      if let data = Data(base64Encoded: base64) {
        return Pairing(pairingData: [UInt8](data))
      } else {
        throw SmartCardError.invalidBase64
      }
    }

    func logAppInfo(_ info: ApplicationInfo) -> Void {
      os_log("Instance UID: %@", bytesToHex(info.instanceUID))
      os_log("Key UID: %@", bytesToHex(info.keyUID))
      os_log("Secure channel public key: %@", bytesToHex(info.secureChannelPubKey))
      os_log("Application version: %@", info.appVersionString)
      os_log("Free pairing slots: %d", info.freePairingSlots)
    }

    func logSignature(_ hash: [UInt8], _ signature: RecoverableSignature) -> Void {
      os_log("Signed hash: %@", bytesToHex(hash))
      os_log("Recovery ID: %d", signature.recId)
      os_log("R: %@", bytesToHex(signature.r))
      os_log("S: %@", bytesToHex(signature.s))
    }

    func formatSignature(_ signature: RecoverableSignature) -> String {
      var out = Data(signature.r)
      out.append(contentsOf: signature.s)
      out.append(contentsOf: [signature.recId])
      let sig = dataToHex(out)

      os_log("Signature: %@", sig)
      return sig
    }

    func dataToHex(_ data: Data) -> String {
      return data.map { String(format: "%02hhx", $0) }.joined()
    }

    func bytesToHex(_ bytes: [UInt8]) -> String {
      return bytes.map { String(format: "%02hhx", $0) }.joined()
    }

    func hexToBytes(_ hex: String) -> [UInt8] {
      let h = hex.starts(with: "0x") ? String(hex.dropFirst(2)) : hex

      var last = h.first
        return h.dropFirst().compactMap {
          guard
            let lastHexDigitValue = last?.hexDigitValue,
            let hexDigitValue = $0.hexDigitValue
          else {
            last = $0
            return nil
          }
      defer {
        last = nil
      }
        return UInt8(lastHexDigitValue * 16 + hexDigitValue)
      }
    }
}

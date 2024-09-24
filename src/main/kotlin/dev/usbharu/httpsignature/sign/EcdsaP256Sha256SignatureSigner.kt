package dev.usbharu.httpsignature.sign

import java.security.PrivateKey
import java.security.Signature
import java.util.*

class EcdsaP256Sha256SignatureSigner : SignatureSigner {
    override fun sign(byteArray: ByteArray, privateKey: PrivateKey): String {
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(privateKey)
        signature.update(byteArray)
        return Base64.getEncoder().encodeToString(signature.sign())
    }
}
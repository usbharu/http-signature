package dev.usbharu.httpsignature.v2

import java.security.PublicKey
import java.security.Signature

class RsaV1_5Sha256SignatureVerifier : SignatureVerifier {
    override fun verify(byteArray: ByteArray, signature: ByteArray, publicKey: PublicKey): Boolean {
        val instance = Signature.getInstance("SHA256withRSA")
        instance.initVerify(publicKey)
        instance.update(byteArray)
        return instance.verify(signature)
    }
}
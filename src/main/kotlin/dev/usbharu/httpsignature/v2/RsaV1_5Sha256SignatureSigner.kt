package dev.usbharu.httpsignature.v2

import java.security.PrivateKey
import java.security.Signature
import java.util.*

/**
 * RSASSA-PKCS1-v1.5
 */

class RsaV1_5Sha256SignatureSigner : SignatureSigner {
    override fun sign(byteArray: ByteArray, privateKey: PrivateKey): String {
        val signature = Signature.getInstance("SHA256withRSA")
        signature.initSign(privateKey)
        signature.update(byteArray)
        val bytes = signature.sign()

        return Base64.getEncoder().encodeToString(bytes)
    }
}
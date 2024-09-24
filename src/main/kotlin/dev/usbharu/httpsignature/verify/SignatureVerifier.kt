package dev.usbharu.httpsignature.verify

import java.security.PublicKey

interface SignatureVerifier {
    fun verify(byteArray: ByteArray, signature: ByteArray, publicKey: PublicKey): Boolean
}
package dev.usbharu.httpsignature.v2

import java.security.PublicKey

interface SignatureVerifier {
    fun verify(byteArray: ByteArray, signature: ByteArray, publicKey: PublicKey): Boolean
}
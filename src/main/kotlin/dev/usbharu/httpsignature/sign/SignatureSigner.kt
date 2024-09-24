package dev.usbharu.httpsignature.sign

import java.security.PrivateKey

interface SignatureSigner {
    fun sign(byteArray: ByteArray,privateKey: PrivateKey): String
}
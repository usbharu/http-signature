package dev.usbharu.httpsignature.v2

import java.security.PrivateKey

interface SignatureSigner {
    fun sign(byteArray: ByteArray,privateKey: PrivateKey): String
}
package dev.usbharu.httpsignature.v2

import java.security.PrivateKey

data class Material(
    val signatureBase: SignatureBase,
    val privateKey: PrivateKey,
    val label: String
)

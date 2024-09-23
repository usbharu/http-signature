package dev.usbharu.httpsignature.v2

import java.security.PublicKey

data class VerifyMaterial(
    val signatureBase: SignatureBase,
    val publicKey: PublicKey,
    val label: String
)

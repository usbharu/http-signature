package dev.usbharu.httpsignature.verify

import dev.usbharu.httpsignature.common.SignatureBase
import java.security.PublicKey

data class VerifyMaterial(
    val signatureBase: SignatureBase,
    val publicKey: PublicKey,
    val label: String
)

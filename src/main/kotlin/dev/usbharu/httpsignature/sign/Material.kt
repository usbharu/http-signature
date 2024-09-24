package dev.usbharu.httpsignature.sign

import dev.usbharu.httpsignature.common.SignatureBase
import java.security.PrivateKey

data class Material(
    val signatureBase: SignatureBase,
    val privateKey: PrivateKey,
    val label: String
)

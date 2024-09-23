package dev.usbharu.httpsignature.v2

import java.time.Instant

data class SignatureParameter(
    val algorithm: SignatureAlgorithm?,
    val keyId: String?,
    val created: Instant?,
    val expires: Instant?,
    val nonce: String?,
    val tag: String?,
)

package dev.usbharu.httpsignature.v2

import java.time.Instant

data class SignatureParameter(
    val algorithm: SignatureAlgorithm? = null,
    val keyId: String? = null,
    val created: Instant? = null,
    val expires: Instant? = null,
    val nonce: String? = null,
    val tag: String? = null,
)

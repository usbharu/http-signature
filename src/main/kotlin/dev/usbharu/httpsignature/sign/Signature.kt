package dev.usbharu.httpsignature.sign

import dev.usbharu.httpsignature.common.HttpRequest

@Deprecated("")
data class Signature(
    val request: HttpRequest,
    val signature: String,
    val signatureHeader: String
)

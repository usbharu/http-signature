package dev.usbharu.httpsignature.sign

import dev.usbharu.httpsignature.common.HttpRequest

data class Signature(
    val request: HttpRequest,
    val signature: String,
    val signatureHeader: String
)

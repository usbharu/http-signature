package dev.usbharu.httpsignature.verify

import dev.usbharu.httpsignature.common.HttpHeaders

interface SignatureHeaderParser {
    fun parse(httpHeaders: HttpHeaders):Signature
}

package dev.usbharu.httpsignature.verify

import dev.usbharu.httpsignature.common.HttpHeaders

@Deprecated("")
interface SignatureHeaderParser {
    fun parse(httpHeaders: HttpHeaders):Signature
}

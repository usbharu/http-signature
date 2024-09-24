package dev.usbharu.httpsignature.verify

import dev.usbharu.httpsignature.common.Signature

interface HttpSignatureHeaderParser {
    fun parse(signatureInputs: List<String>, signatures: List<String>): Map<String, Signature>
}
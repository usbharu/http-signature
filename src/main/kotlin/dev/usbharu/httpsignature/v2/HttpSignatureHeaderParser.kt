package dev.usbharu.httpsignature.v2

interface HttpSignatureHeaderParser {
    fun parse(signatureInputs: List<String>, signatures: List<String>): Map<String, Signature>
}
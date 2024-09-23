package dev.usbharu.httpsignature.v2

data class Signature(
    val label: String,
    val signatureInput: String,
    val signature: String,
    val signatureParameters: List<SignatureParameter>,
    val coveredComponents: List<String>
)

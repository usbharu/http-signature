package dev.usbharu.httpsignature.common

data class Signature(
    val label: String,
    val signatureInput: String,
    val signature: String,
    val signatureParameters: List<SignatureParameter>,
    val coveredComponents: List<String>
)

package dev.usbharu.httpsignature.common

interface SignatureBase {
    fun generateSignatureBase(signatureParameters: List<SignatureParameter>): String
    fun generateSignatureParameterString(signatureParameters: List<SignatureParameter>): String
    fun coveredComponents(): List<String>
}
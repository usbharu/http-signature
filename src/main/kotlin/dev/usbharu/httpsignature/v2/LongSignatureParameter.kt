package dev.usbharu.httpsignature.v2

data class LongSignatureParameter(val longName: String, val longValue: Long) : SignatureParameter {
    override val name: String
        get() = longName
    override val value: String
        get() = longValue.toString()
}
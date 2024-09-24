package dev.usbharu.httpsignature.common

data class StringSignatureParameter(private val stringName: String, private val stringValue: String) :
    SignatureParameter {
    override val name: String
        get() = stringName
    override val value: String
        get() = "\"$stringValue\""
}
package dev.usbharu.httpsignature.common

import java.time.Instant

data class InstantSignatureParameter(private val instantName: String, val instant: Instant) : SignatureParameter {
    override val name: String
        get() = instantName
    override val value: String
        get() = instant.epochSecond.toString()
}
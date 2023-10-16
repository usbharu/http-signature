package dev.usbharu.httpsignature.verify

sealed class VerificationResult(val success: Boolean)

class SuccessfulVerification : VerificationResult(true)

open class FailedVerification(val reason:String) : VerificationResult(false)

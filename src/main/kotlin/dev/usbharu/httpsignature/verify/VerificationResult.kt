package dev.usbharu.httpsignature.verify

@Deprecated("")
sealed class VerificationResult(val success: Boolean)

@Deprecated("")
class SuccessfulVerification : VerificationResult(true)

@Deprecated("")
open class FailedVerification(val reason: String) : VerificationResult(false)

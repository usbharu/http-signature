package dev.usbharu.httpsignature.verify

import dev.usbharu.httpsignature.common.HttpRequest
import dev.usbharu.httpsignature.common.PublicKey

interface HttpSignatureVerifier {
    fun verify(httpRequest: HttpRequest,key: PublicKey):VerificationResult
}

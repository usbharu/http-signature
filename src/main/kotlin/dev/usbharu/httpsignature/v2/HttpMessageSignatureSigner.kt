package dev.usbharu.httpsignature.v2

import dev.usbharu.httpsignature.common.HttpRequest
import java.security.PrivateKey

class HttpMessageSignatureSigner {
    fun sign(httpRequest: HttpRequest,privateKey: PrivateKey)
}
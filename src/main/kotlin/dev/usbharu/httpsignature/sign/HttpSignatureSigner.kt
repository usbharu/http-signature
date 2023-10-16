package dev.usbharu.httpsignature.sign

import dev.usbharu.httpsignature.common.HttpHeaders
import dev.usbharu.httpsignature.common.HttpMethod
import dev.usbharu.httpsignature.common.HttpRequest
import dev.usbharu.httpsignature.common.PrivateKey
import java.net.URL

interface HttpSignatureSigner {
    fun sign(httpRequest: HttpRequest, privateKey: PrivateKey, signHeaders: List<String>): Signature
    fun signRaw(signString: String, privateKey: PrivateKey, signHeaders: List<String>): String
    fun buildSignString(
        url: URL,
        method: HttpMethod,
        headers: HttpHeaders,
        signHeaders: List<String>
    ): String
}

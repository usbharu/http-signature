package dev.usbharu.httpsignature.sign

import dev.usbharu.httpsignature.common.HttpRequest
import dev.usbharu.httpsignature.common.PrivateKey
import java.util.*

class RsaSha256HttpSignatureSigner : AbstractHttpSignatureSigner() {
    override fun sign(httpRequest: HttpRequest, privateKey: PrivateKey, signHeaders: List<String>): Signature {
        val buildSignString = buildSignString(httpRequest.url, httpRequest.method, httpRequest.headers, signHeaders)
        val signature = signRaw(buildSignString, privateKey, signHeaders)

        val signatureHeader =
            """keyId="${privateKey.keyId}",algorithm="rsa-sha256",headers="${signHeaders.joinToString(" ")}",signature="$signature""""

        val request = httpRequest.copy(headers = httpRequest.headers.plus("Signature", listOf(signatureHeader)))
        return Signature(request, signature, signatureHeader)

    }

    override fun signRaw(signString: String, privateKey: PrivateKey, signHeaders: List<String>): String {
        val signer = java.security.Signature.getInstance("SHA256withRSA")
        signer.initSign(privateKey.privateKey)
        signer.update(signString.toByteArray())
        val sign = signer.sign()
        return Base64.getEncoder().encodeToString(sign)
    }
}

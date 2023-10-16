package dev.usbharu.httpsignature.sign

import dev.usbharu.httpsignature.common.HttpHeaders
import dev.usbharu.httpsignature.common.HttpMethod
import dev.usbharu.httpsignature.common.HttpRequest
import dev.usbharu.httpsignature.common.PrivateKey
import java.net.URL
import java.util.*

class HttpSignatureSignerImpl : HttpSignatureSigner {
    override fun sign(httpRequest: HttpRequest, privateKey: PrivateKey, signHeaders: List<String>): Signature {
        val buildSignString = buildSignString(httpRequest.url, httpRequest.method, httpRequest.headers, signHeaders)
        val signature = signRaw(buildSignString, privateKey, signHeaders)

        val signatureHeader =
            """keyId="${privateKey.keyId}",algorithm="rsa-sha256",headers="${signHeaders.joinToString(" ")}",signature="$signature""""

        return Signature(httpRequest, signature, signatureHeader)

    }

    override fun signRaw(signString: String, privateKey: PrivateKey, signHeaders: List<String>): String {
        val signer = java.security.Signature.getInstance("SHA256withRSA")
        signer.initSign(privateKey.privateKey)
        signer.update(signString.toByteArray())
        val sign = signer.sign()
        return Base64.getEncoder().encodeToString(sign)
    }

    override fun buildSignString(
        url: URL,
        method: HttpMethod,
        headers: HttpHeaders,
        signHeaders: List<String>
    ): String {
        val result = signHeaders.joinToString("\n") {
            if (it.startsWith("(")) {
                specialHeader(it, url, method)
            } else {
                generalHeader(it, headers.get(it)!!)
            }
        }
        return result
    }

    private fun specialHeader(fieldName: String, url: URL, method: HttpMethod): String {
        if (fieldName != "(request-target)") {
            throw IllegalArgumentException(fieldName + "is unsupported type")
        }
        return "(request-target): ${method.value.lowercase()} ${url.path}"
    }

    // TODO: 複数ヘッダーの正規化をする
    private fun generalHeader(fieldName: String, value: List<String>): String = "$fieldName: ${value.first()}"
}

package dev.usbharu.httpsignature.sign

import dev.usbharu.httpsignature.common.HttpMethod
import dev.usbharu.httpsignature.common.HttpRequest
import dev.usbharu.httpsignature.common.PrivateKey
import java.net.URL
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.time.Instant
import java.util.*

class Hs2019HttpSignatureSigner(private val expires: Long,private val salt:Int = 64) :
    AbstractHttpSignatureSigner() {
    override fun sign(httpRequest: HttpRequest, privateKey: PrivateKey, signHeaders: List<String>): Signature {
        val buildSignString = buildSignString(httpRequest.url, httpRequest.method, httpRequest.headers, signHeaders)
        val signature = signRaw(buildSignString, privateKey, signHeaders)

        val split = buildSignString.split("\n")

        val created = if (signHeaders.contains("(created)")) {
            ",created=\"${split.first { it.startsWith("(created)") }.substringAfterLast(": ")}\""
        } else {
            ""
        }
        val expires = if (signHeaders.contains("(expires)")) {
            ",expires=\"${split.first { it.startsWith("(expires)") }.substringAfterLast(": ")}\""
        } else {
            ""
        }

        val signatureHeader =
            """keyId="${privateKey.keyId}",algorithm="hs2019"$created$expires,headers="${signHeaders.joinToString(" ")}",signature="$signature""""

        val request = httpRequest.copy(headers = httpRequest.headers.plus("Signature", listOf(signatureHeader)))
        return Signature(request, signature, signatureHeader)
    }

    override fun signRaw(signString: String, privateKey: PrivateKey, signHeaders: List<String>): String {
        val signer = java.security.Signature.getInstance("RSASSA-PSS")
        signer.setParameter(PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, salt, 1))
        signer.initSign(privateKey.privateKey)
        signer.update(signString.toByteArray())
        val sign = signer.sign()
        return Base64.getEncoder().encodeToString(sign)
    }

    @Throws(IllegalArgumentException::class)
    override fun specialHeader(fieldName: String, url: URL, method: HttpMethod): String {
        return when (fieldName) {
            "(request-target)" -> {
                "(request-target): ${method.value.lowercase()} ${url.path}"
            }

            "(created)" -> {
                "(created): ${Instant.now().epochSecond}"
            }

            "(expires)" -> {
                "(expires): ${Instant.now().plusSeconds(expires).epochSecond}"
            }

            else -> {
                throw IllegalArgumentException("${fieldName}is unsupported type.")
            }
        }
    }
}

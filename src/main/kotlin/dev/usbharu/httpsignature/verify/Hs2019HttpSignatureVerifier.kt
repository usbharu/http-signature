package dev.usbharu.httpsignature.verify

import dev.usbharu.httpsignature.common.HttpHeaders
import dev.usbharu.httpsignature.common.HttpMethod
import dev.usbharu.httpsignature.common.HttpRequest
import dev.usbharu.httpsignature.common.PublicKey
import java.net.URL
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.time.Instant
import java.util.*

class Hs2019HttpSignatureVerifier(
    private val signatureHeaderParser: SignatureHeaderParser,
    private val salt: Int = 64
) : HttpSignatureVerifier {
    override fun verify(httpRequest: HttpRequest, key: PublicKey): VerificationResult {
        val signature = signatureHeaderParser.parse(httpRequest.headers)
        if (signature.algorithm.equals("hs2019", true).not()) {
            return FailedVerification("Unsupported algorithm : ${signature.algorithm}")
        }

        if (signature.keyId != key.keyId) {
            return FailedVerification("The keyId is different.")
        }

        val created = if (signature.headers.contains("(created)")) {
            val created = signature.additionalData["created"]
                ?: return FailedVerification("(created) header is provided, but it does not exist.")
            val l = created.toLongOrNull() ?: return FailedVerification("(created) is an unsupported format.")
            if (Instant.ofEpochSecond(l) >= Instant.now()) {
                return FailedVerification("(created) is the future.")
            }
            l
        } else {
            null
        }

        val expires = if (signature.headers.contains("(expires)")) {
            val expires = (signature.additionalData["expires"]
                ?: return FailedVerification("(expires) header is provided, but it does not exist."))
            val l = expires.toLongOrNull() ?: return FailedVerification("(expires) is an unsupported format.")
            if (Instant.ofEpochSecond(l) <= Instant.now()) {
                return FailedVerification("(expires) is expired.")
            }
            l
        } else {
            null
        }


        val byteSignature = Base64.getDecoder().decode(signature.signature)


        val buildSignString =
            buildSignString(
                url = httpRequest.url,
                method = httpRequest.method,
                headers = httpRequest.headers,
                signHeaders = signature.headers,
                created = created,
                expires = expires
            )

        val verifier = java.security.Signature.getInstance("RSASSA-PSS")
        verifier.setParameter(PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, salt, 1))
        verifier.initVerify(key.publicKey)
        verifier.update(buildSignString.toByteArray())
        val verify = verifier.verify(byteSignature)

        if (verify) {
            return SuccessfulVerification()
        }
        return FailedVerification("Signature verification failed.")
    }

    private fun generalHeader(fieldName: String, value: List<String>): String = "$fieldName: ${value.first()}"

    private fun buildSignString(
        url: URL,
        method: HttpMethod,
        headers: HttpHeaders,
        signHeaders: List<String>,
        created: Long?,
        expires: Long?
    ): String {
        return signHeaders.joinToString("\n") {
            when (it) {
                "(request-target)" -> {
                    "(request-target): ${method.value.lowercase()} ${url.path}"
                }

                "(created)" -> {
                    "(created): ${created!!}"
                }

                "(expires)" -> {
                    "(expires): ${expires!!}"
                }

                else -> {
                    generalHeader(it, headers.get(it)!!)
                }
            }
        }
    }
}

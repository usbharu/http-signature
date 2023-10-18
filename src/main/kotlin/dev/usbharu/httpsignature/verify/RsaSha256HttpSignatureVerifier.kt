package dev.usbharu.httpsignature.verify

import dev.usbharu.httpsignature.common.HttpRequest
import dev.usbharu.httpsignature.common.PublicKey
import dev.usbharu.httpsignature.sign.HttpSignatureSigner
import java.security.Signature
import java.util.*

class RsaSha256HttpSignatureVerifier(
    private val signatureHeaderParser: SignatureHeaderParser,
    private val httpSignatureSigner: HttpSignatureSigner
) : HttpSignatureVerifier {
    override fun verify(httpRequest: HttpRequest, key: PublicKey): VerificationResult {
        val signature = signatureHeaderParser.parse(httpRequest.headers)
        if (signature.algorithm.equals("rsa-sha256", true).not()) {
            return FailedVerification("Unsupported algorithm : ${signature.algorithm}")
        }

        if (signature.keyId != key.keyId) {
            return FailedVerification("The keyid is different.")
        }

        val byteSignature = Base64.getDecoder().decode(signature.signature)

        val buildSignString = httpSignatureSigner.buildSignString(
            httpRequest.url, httpRequest.method, httpRequest.headers, signature.headers
        )

        val signer = Signature.getInstance("SHA256withRSA")
        signer.initVerify(key.publicKey)
        signer.update(buildSignString.toByteArray())
        val verify = signer.verify(byteSignature)

        if (verify) {
            return SuccessfulVerification()
        }

        return FailedVerification("Signature verification failed.")
    }
}

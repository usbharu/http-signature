package dev.usbharu.httpsignature.v2

import java.util.*

class HttpMessageSignatureVerifier {
    fun verify(verifyMaterial: VerifyMaterial, signature: Signature, signatureVerifier: SignatureVerifier): Boolean {
        val coveredComponents = verifyMaterial.signatureBase.coveredComponents()
        signature.coveredComponents.all { coveredComponents.contains(it) }

        val signatureBase = verifyMaterial.signatureBase.generateSignatureBase(signature.signatureParameters)

        return signatureVerifier.verify(
            signatureBase.toByteArray(Charsets.UTF_8),
            Base64.getDecoder().decode(signature.signature),
            verifyMaterial.publicKey
        )

    }
}
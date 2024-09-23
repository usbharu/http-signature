package dev.usbharu.httpsignature.v2

import dev.usbharu.httpsignature.common.HttpRequest
import java.security.PrivateKey

class HttpMessageSignatureSigner {
    fun sign(material: Material, signatureParameter: SignatureParameter, signer: SignatureSigner): Signatures {

        val signatureBase = material.signatureBase.generateSignatureBase(signatureParameter)
        val signatureInput =
            "${material.label}=" + material.signatureBase.generateSignatureParameterString(signatureParameter)

        val signature = signer.sign(signatureBase.toByteArray(Charsets.UTF_8), material.privateKey)

        return Signatures(signatureInput, signature)
    }
}
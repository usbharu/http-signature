package dev.usbharu.httpsignature.v2

class HttpMessageSignatureSigner {
    fun sign(material: Material, signatureParameters: List<SignatureParameter>, signer: SignatureSigner): Signature {

        val signatureBase = material.signatureBase.generateSignatureBase(signatureParameters)
        val signatureInput =
            "${material.label}=" + material.signatureBase.generateSignatureParameterString(signatureParameters)

        val signature = signer.sign(signatureBase.toByteArray(Charsets.UTF_8), material.privateKey)

        return Signature(
            material.label,
            signatureInput,
            signature,
            signatureParameters,
            material.signatureBase.coveredComponents()
        )
    }
}
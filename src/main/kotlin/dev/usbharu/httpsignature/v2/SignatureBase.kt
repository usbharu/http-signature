package dev.usbharu.httpsignature.v2

class SignatureBase() {

    private val list = mutableMapOf<String, Component>()

    fun addComponent(component: Component) {
        if (list[component.componentIdentifier] != null) {
            throw IllegalArgumentException("Component with identifier ${component.componentIdentifier} already exists.")
        }
        list[component.componentIdentifier] = component
    }

    fun generateSignatureBase(signatureParameter: SignatureParameter): String {
        val signatureBase =
            list.values.joinToString(separator = "",postfix = "\n") { component -> "${component.componentIdentifier}: ${component.componentValue}" }

        val signatureParams = "\"@signature-params\": " + generateSignatureParameterString(signatureParameter)

        return signatureBase + signatureParams
    }

    fun generateSignatureParameterString(signatureParameter: SignatureParameter): String {
        return listOfNotNull(
            list.keys.joinToString(" ", "(", ")"),
            signatureParameter.algorithm?.let { algorithm -> "alg=\"${algorithm.value}\"" },
            signatureParameter.keyId?.let { keyId -> "keyid=\"$keyId\"" },
            signatureParameter.created?.let { created -> "created=$created" },
            signatureParameter.expires?.let { expires -> "expires=$expires" },
            signatureParameter.nonce?.let { nonce -> "nonce=\"$nonce\"" },
            signatureParameter.tag?.let { tag -> "tag=\"$tag\"" },
        ).joinToString(";")
    }
}

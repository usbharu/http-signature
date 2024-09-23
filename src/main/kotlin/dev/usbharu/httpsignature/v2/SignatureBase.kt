package dev.usbharu.httpsignature.v2

class SignatureBase() {

    private val list = mutableListOf<Component>()

    fun addComponent(component: Component) {
        if (list.indexOf(component) != -1) {
            throw IllegalArgumentException("Component with identifier ${component.componentIdentifier} already exists.")
        }
        list.add(component)
    }

    fun generateSignatureBase(signatureParameters: List<SignatureParameter>): String {
        val signatureBase =
            list.joinToString(
                separator = "",
                postfix = "\n"
            ) { component -> "${component.componentIdentifier}: ${component.componentValue}" }

        val signatureParams = "\"@signature-params\": " + generateSignatureParameterString(signatureParameters)

        return signatureBase + signatureParams
    }

    fun generateSignatureParameterString(signatureParameters: List<SignatureParameter>): String {
        return (listOf(
            list.joinToString(
                " ",
                "(",
                ")"
            ) { it.componentIdentifier }
        ) + signatureParameters.map { "${it.name}=${it.value}" }).joinToString(";")
    }

    fun coveredComponents(): List<String> {
        return list.map { it.componentIdentifier }
    }
}

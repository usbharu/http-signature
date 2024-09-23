package dev.usbharu.httpsignature.v2

class SignatureBase() {

    private val list = mutableMapOf<String, Component>()

    fun addComponent(component: Component) {
        if (list[component.componentIdentifier] != null) {
            throw IllegalArgumentException("Component with identifier ${component.componentIdentifier} already exists.")
        }
        list[component.componentIdentifier] = component
    }

    fun generateSignatureBase(signatureParameters: List<SignatureParameter>): String {
        val signatureBase =
            list.values.joinToString(
                separator = "",
                postfix = "\n"
            ) { component -> "${component.componentIdentifier}: ${component.componentValue}" }

        val signatureParams = "\"@signature-params\": " + generateSignatureParameterString(signatureParameters)

        return signatureBase + signatureParams
    }

    fun generateSignatureParameterString(signatureParameters: List<SignatureParameter>): String {
        return (listOf(
            list.keys.joinToString(
                " ",
                "(",
                ")"
            )
        ) + signatureParameters.map { "${it.name}=${it.value}" }).joinToString(";")
    }

    fun coveredComponents(): List<String> {
        return list.map { it.key }
    }
}

package dev.usbharu.httpsignature.v2

interface Component {
    val componentName: String
    val componentIdentifier: String
        get() {
            if (componentParameter.isBlank()) {
                return "\"$componentName\""
            }
            return "\"$componentName\";$componentParameter"
        }
    val componentParameter: String
    val componentValue: String
}

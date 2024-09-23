package dev.usbharu.httpsignature.v2

interface Component {
    val componentName: String
    val componentIdentifier: String
        get() = "\"$componentName\":$componentParameter"
    val componentParameter: String
    val componentValue: String
}

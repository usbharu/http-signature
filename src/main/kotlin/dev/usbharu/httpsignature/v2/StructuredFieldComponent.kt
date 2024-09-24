package dev.usbharu.httpsignature.v2

import org.greenbytes.http.sfv.Type

class StructuredFieldComponent(val name: String, val structuredField: Type<*>) : Component {
    override val componentName: String
        get() = name
    override val componentParameter: String
        get() = "sf"
    override val componentValue: String
        get() = structuredField.serialize()
}
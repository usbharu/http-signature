package dev.usbharu.httpsignature.v2

import com.sun.org.apache.xerces.internal.util.XMLChar.trim

class HttpMessageComponent(private val headerName: String, private val headerValues: List<String>) : Component {
    override val componentName: String
        get() = headerName.lowercase()
    override val componentParameter: String
        get() = ""
    override val componentValue: String
        get() = headerValues.joinToString(", ") { it.replace("\n", " ").trim() }
}
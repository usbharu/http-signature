package dev.usbharu.httpsignature.utils

import dev.usbharu.httpsignature.common.Component
import dev.usbharu.httpsignature.common.HttpRequest

interface HttpRequestComponentExtractor {
    fun extract(name: String, request: HttpRequest): List<Component>
}
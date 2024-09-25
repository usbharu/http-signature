package dev.usbharu.httpsignature.utils

import dev.usbharu.httpsignature.common.Component
import dev.usbharu.httpsignature.common.HttpRequest

abstract class AbstractHttpRequestComponentExtractor(protected val fieldProcessor: FieldProcessor) :
    HttpRequestComponentExtractor {
    override fun extract(name: String, request: HttpRequest): List<Component> {
        val extractValue = extractValue(name, request)
        return fieldProcessor.process(name, extractValue)
    }

    abstract fun extractValue(name: String, request: HttpRequest): List<String>
}
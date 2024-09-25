package dev.usbharu.httpsignature.utils

import dev.usbharu.httpsignature.common.HttpRequest
import dev.usbharu.httpsignature.common.SignatureBaseBuilder

class HttpRequestSignatureBaseUtils {

    private val fieldProcessorMap = mutableMapOf<String, HttpRequestComponentExtractor>()

    fun from(httpRequest: HttpRequest, coveredComponents: List<CoveredComponent>): SignatureBaseBuilder {
        val builder = SignatureBaseBuilder()
        coveredComponents
            .flatMap {
                val extractor = (fieldProcessorMap[it.componentParameterType]
                    ?: throw IllegalArgumentException("HttpRequestComponentExtractor ${it.componentParameterType} not found."))
                extractor.extract(it.fieldName, httpRequest)
            }.forEach {
                builder.component(it)
            }
        return builder
    }
}
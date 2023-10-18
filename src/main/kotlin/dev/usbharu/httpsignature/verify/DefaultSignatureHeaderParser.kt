package dev.usbharu.httpsignature.verify

import dev.usbharu.httpsignature.common.HttpHeaders

class DefaultSignatureHeaderParser : SignatureHeaderParser {
    override fun parse(httpHeaders: HttpHeaders): Signature {
        val signatureHeader = httpHeaders.get("Signature").single()

        val parameters = signatureHeader.split(",")
            .map { it.trim() }
            .map { it.trim('"') }
            .map { it.split("=\"") }
            .associate { it[0].split(" ").last() to it[1].trim('"') }
            .toMutableMap()
        return Signature(
            parameters.remove("keyId")!!,
            parameters.remove("algorithm")!!,
            parameters.remove("headers")?.split(" ")!!,
            parameters.remove("signature")!!,
            parameters
        )
    }
}

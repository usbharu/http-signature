package dev.usbharu.httpsignature.v2

import org.greenbytes.http.sfv.*
import java.util.*

class DefaultHttpSignatureHeaderParser() : HttpSignatureHeaderParser {
    override fun parse(signatureInputs: List<String>, signatures: List<String>): Map<String, Signature> {
        val signatureInputString = signatureInputs.joinToString(", ")

        val signatureString = signatures.joinToString(", ")

        val parseSignatureInputs = parseSignatureInputs(signatureInputString)

        val parseSignatures = parseSignatures(signatureString)

        require(parseSignatureInputs.size == parseSignatures.size)

        return parseSignatureInputs.map {
            val signatureInput = parseSignatureInputs.getValue(it.key)
            it.key to Signature(
                it.key,
                signatureInput.first,
                parseSignatures.getValue(it.key),
                signatureInput.third,
                signatureInput.second
            )
        }.toMap()
    }

    private fun parseSignatureInputs(signatureInput: String): Map<String, Triple<String, List<String>, List<SignatureParameter>>> {
        val parser = Parser(signatureInput)
        val map = parser.parseDictionary()
            .get()
            .mapValues {
                val innerList = it.value as InnerList
                Triple(
                    it.value.serialize(),
                    innerList.get().map { it.get().toString() },
                    innerList.params.map { param ->
                        when (val value = param.value) {
                            is IntegerItem -> LongSignatureParameter(param.key, value.asLong)
                            is NumberItem -> LongSignatureParameter(param.key, value.asLong)
                            is StringItem -> StringSignatureParameter(param.key, value.get())
                            else -> error("Unknown parameter: $param")
                        }
                    }
                )
            }

        return map
    }

    private fun parseSignatures(signature: String): Map<String, String> {
        val parser = Parser(signature)
        val map = parser.parseDictionary().get()

        return map.map { it.key to Base64.getEncoder().encodeToString((it.value as ByteSequenceItem).get().array()) }
            .toMap()
    }
}
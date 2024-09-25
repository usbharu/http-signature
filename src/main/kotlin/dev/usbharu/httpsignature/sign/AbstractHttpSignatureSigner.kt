package dev.usbharu.httpsignature.sign

import dev.usbharu.httpsignature.common.HttpHeaders
import dev.usbharu.httpsignature.common.HttpMethodBase
import java.net.URL

@Deprecated("")
abstract class AbstractHttpSignatureSigner : HttpSignatureSigner {
    override fun buildSignString(
        url: URL,
        method: HttpMethodBase,
        headers: HttpHeaders,
        signHeaders: List<String>
    ): String {
        val result = signHeaders.joinToString("\n") {
            if (it.startsWith("(")) {
                specialHeader(it, url, method)
            } else {
                generalHeader(it, headers.get(it)!!)
            }
        }
        return result
    }

    protected open fun specialHeader(fieldName: String, url: URL, method: HttpMethodBase): String {
        if (fieldName != "(request-target)") {
            throw IllegalArgumentException(fieldName + "is unsupported type")
        }
        return "(request-target): ${method.methodName.lowercase()} ${url.path}"
    }

    // TODO: 複数ヘッダーの正規化をする
    protected open fun generalHeader(fieldName: String, value: List<String>): String = "$fieldName: ${value.first()}"
}

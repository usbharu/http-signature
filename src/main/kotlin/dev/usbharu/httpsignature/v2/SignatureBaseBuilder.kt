package dev.usbharu.httpsignature.v2

import java.net.http.HttpRequest
import kotlin.jvm.optionals.getOrNull

class SignatureBaseBuilder {
    private val signatureBase = SignatureBase()

    fun build(): SignatureBase {
        return signatureBase
    }

    fun method(method: String): SignatureBaseBuilder {
        signatureBase.addComponent(DerivedComponent(DerivedComponentConstants.METHOD, "", method))
        return this
    }

    fun query(query: String): SignatureBaseBuilder {
        require(query[0] == '?')
        signatureBase.addComponent(DerivedComponent(DerivedComponentConstants.QUERY, "", query))
        return this
    }

    fun targetUri(uri: String): SignatureBaseBuilder {
        signatureBase.addComponent(DerivedComponent(DerivedComponentConstants.TARGET_URI, "", uri))
        return this
    }

    fun authority(authority: String): SignatureBaseBuilder {
        signatureBase.addComponent(DerivedComponent(DerivedComponentConstants.AUTHORITY, "", authority))
        return this
    }

    fun scheme(scheme: String): SignatureBaseBuilder {
        signatureBase.addComponent(DerivedComponent(DerivedComponentConstants.SCHEME, "", scheme))
        return this
    }

    fun requestTarget(requestTarget: String): SignatureBaseBuilder {
        signatureBase.addComponent(DerivedComponent(DerivedComponentConstants.REQUEST_TARGET, "", requestTarget))
        return this
    }

    fun path(path: String): SignatureBaseBuilder {
        signatureBase.addComponent(DerivedComponent(DerivedComponentConstants.PATH, "", path))
        return this
    }

    fun queryParameter(key: String, value: String): SignatureBaseBuilder {
        signatureBase.addComponent(DerivedComponent(DerivedComponentConstants.QUERY_PARAMETER, "name=\"$key\"", value))
        return this
    }

    fun status(code: Int): SignatureBaseBuilder {
        signatureBase.addComponent(DerivedComponent(DerivedComponentConstants.STATUS, "", code.toString()))
        return this
    }

    fun header(headerName:String,headerValues:List<String>): SignatureBaseBuilder {
        signatureBase.addComponent(HttpMessageComponent(headerName, headerValues))
        return this
    }

    fun header(headerName: String,headerValue:String): SignatureBaseBuilder {
        return header(headerName, listOf(headerValue))
    }

    companion object {
        fun fromHttpRequest(httpRequest: HttpRequest): SignatureBaseBuilder {
            val signatureBaseBuilder = SignatureBaseBuilder()
            signatureBaseBuilder.method(httpRequest.method())
            val uri = httpRequest.uri()

            signatureBaseBuilder.query(uri.rawQuery.orEmpty())
            signatureBaseBuilder.targetUri(uri.toString())

            val headers = httpRequest.headers()

            val authority = headers.firstValue("Host").getOrNull()
            if (authority != null) {
                signatureBaseBuilder.authority(authority)
            }

            signatureBaseBuilder.scheme(uri.scheme)
            signatureBaseBuilder.requestTarget(
                uri.rawPath + if ((uri.rawQuery == null)) {
                    ""
                } else {
                    "?${uri.rawQuery}"
                }
            )

            return signatureBaseBuilder
        }
    }
}

object DerivedComponentConstants {
    const val METHOD = "@method"
    const val QUERY = "@query"
    const val TARGET_URI = "@target-uri"
    const val AUTHORITY = "@authority"
    const val SCHEME = "@scheme"
    const val REQUEST_TARGET = "@request-target"
    const val PATH = "@path"
    const val QUERY_PARAMETER = "@query-parameter"
    const val STATUS = "@stats"
}
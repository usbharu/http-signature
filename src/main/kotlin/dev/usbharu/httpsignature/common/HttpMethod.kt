package dev.usbharu.httpsignature.common

enum class HttpMethod(val value: String, override val methodName: String) : HttpMethodBase {
    GET("get", "GET"),
    POST("post", "POST")
}

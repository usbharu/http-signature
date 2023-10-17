package dev.usbharu.httpsignature.common

import java.net.URL

data class HttpRequest(val url: URL, val headers: HttpHeaders, val method: HttpMethod)

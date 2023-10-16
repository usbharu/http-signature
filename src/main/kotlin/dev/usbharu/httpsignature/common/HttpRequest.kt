package dev.usbharu.httpsignature.common

import java.net.URL

class HttpRequest(val url: URL, val headers: HttpHeaders, val method: HttpMethod)

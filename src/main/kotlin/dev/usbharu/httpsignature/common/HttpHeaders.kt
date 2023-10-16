package dev.usbharu.httpsignature.common

class HttpHeaders(headers: Map<String, List<String>>) {
    private val map = mutableMapOf<String, List<String>>()

    init {
        map.putAll(headers.map { it.key.lowercase() to it.value })
    }

    fun get(key: String): List<String> {
        return map.get(key.lowercase()) ?: throw IllegalArgumentException("Header $key was not found.")
    }

    fun plus(key: String, value: List<String>): HttpHeaders {
        return HttpHeaders(map.plus(key to value))
    }
}

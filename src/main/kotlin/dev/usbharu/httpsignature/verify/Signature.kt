package dev.usbharu.httpsignature.verify

data class Signature(
    val keyId:String,
    val algorithm:String,
    val headers:List<String>,
    val signature:String
)

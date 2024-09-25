package dev.usbharu.httpsignature.utils

import dev.usbharu.httpsignature.common.Component

fun interface FieldProcessor {
    fun process(name: String, value: List<String>): List<Component>
}
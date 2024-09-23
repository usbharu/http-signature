package dev.usbharu.httpsignature.v2

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.security.KeyFactory
import java.security.interfaces.RSAPrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.*

class GenerateSignatureTest {

    val privateKey = Base64.getDecoder().decode(
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDH+8IRQdB9vhej" +
                "eNQqwxlIutt4Xxjg3eZ5XYm7KgR4jAT/q7+cfsz2/fVTNwDOBpG2H1YJZRLUsrVI" +
                "3Pia8k7oFyemYKEUN6kaKioO5C9hB0TaiTGlxAKI7syitvedH1YtHqf4zvqgtI2y" +
                "Lv0NAXja3nUoWZWgZg8ZUHWAGhtHd/BpLiyvlwXAydFHl/eN5u8uCZhQD0bKI5KJ" +
                "qi8Vcs59Q13+ZNHFdgvNjeD+Hc2AdOmbB5HrW2wREgd1sygBcZ77sSLyleeel8+d" +
                "VkDsq/l4MQV5/0PeOn+PI8pJkyQUpqnExqzku354XW9ZE6XjREgBb9M0AEdyBLk5" +
                "+YbZwiqrAgMBAAECggEAIDgmKB7xDDvYFcpIbytHo47B/+ldBL2Q0vTdqn3hLTAX" +
                "OL80URj3b25dsVknPrToPO4HhTP3jgp3Z+nR/oS+Gb5r8O5DMBKs9+jbJdMK9G2g" +
                "tjoW+ZypcTj9VynLSFEy0nTMndVwTlFIkvCRwcqpl07yk9xQXas+ZixZrJiIKeyW" +
                "rCmBDJAjUSknljHDnULxAXvk6K7Y5uqPCv9DQ1362ZopY56H0++9ZMaJwr5PYJMT" +
                "QoKVeZCGLvfY29rUrhV0/CvC7cfxrPbSuQ7Tr/WrpxFpz9H/Dnc8uePoUEmMP2GM" +
                "ozjXaJDQrzOVMOpn/2uGinmrcR5/8ETsYruGG96kAQKBgQDoS4PyiZ93zTv5Yvo/" +
                "aWX5IvieMO/w3kRvsdq0IM27Gd+Ck+0C7WBUqljuU4ql10mp67MFkj7ZmECWCAKa" +
                "OfE3NtXKqnRgixDhM4Q7nfolhkN08CxRrYP3dBh7HJMDtb2YzPDdwV+PSbL6AM8o" +
                "oOvxjABJQk6CaGdmL8sQwnHwgQKBgQDcZCJbwDyLPJo04dXkhPBWoH5hGjbtsAv9" +
                "whhjY9IWFN/0KvJfzfoTWtgCkpYT3wgMYBVp0aTextbg1euim7X+iVL6TRq4QaVk" +
                "Jv6dRnNZPrY7MlnXxIXE81z6syVjChrJBWi81s14SDKtGOpvghLiKUR29wvGjfER" +
                "jY/X1MxFKwKBgAUyOz9fqLuLUb4gYqysdOV/zMPtIFDpB+rftZ615SQ8Te2j1Xdt" +
                "S+xY6yhZog5XpIQyi4yiWtmPOFKi1zwP879icKHZ8kR+l+ARwPF8dS4FtNiWzsb8" +
                "9KjCZhHK79bzZ8xVOUYcn0CbS2+gOQIVp3F9yjvZSdxM7ZMxmn9Dej0BAoGBAJuf" +
                "ZZeOLfJPz8AJvCSKLr+swrDEdwbtqfn8xYXhJacMBHwAm3dFFhH2stNWOP09HwzG" +
                "CDjZnWbl1zOaOrJu61saEurF6Vk0mZoX4vChn6/kFX/FdSVkEuVYx04LlBnUN8e8" +
                "txGpSBtoN8h88IXevoDOjRbIKZuB/Tjc0jagf8FTAoGAWW8uXsWS4c2nBGNdodqL" +
                "xJHcNZVMenHPqdkm7rHEYdf1sdbM7r7Q+oj0cifhbZwaRG9HiRGUAgJerLGEqe+x" +
                "vNeYuKRF3A5xBFUTw/t+XFhUZ1sSyvOordp0uNahQqkAx1UQFWUBCEkG2k/X81fY" +
                "trEnKP2IjOJDzoXGvc4TG0w="
    )

    val pkcS8EncodedKeySpec = PKCS8EncodedKeySpec(privateKey)
    val rsaPrivateKey = KeyFactory.getInstance("RSA").generatePrivate(pkcS8EncodedKeySpec) as RSAPrivateKey

    @Test
    fun name() {


        val signatureBase = SignatureBaseBuilder()
            .header("Host", "example.com")
            .build()

        val material = Material(
            signatureBase,
            rsaPrivateKey,
            "label"
        )

        val signer = HttpMessageSignatureSigner()

        val sign = signer.sign(material, SignatureParameter(), RsaV1_5Sha256SignatureSigner())

        val expectedSignatureBase = "\"host\": example.com\n" +
                "\"@signature-params\": (\"host\")"

        val expectedSignatureValue =
            "Qg8lYdN9pjOjHIOmw6rZoAVAThG5iKM/uqhxHmnGJiFLTN2jF+jJmOmfVhSjQQjkxcJPl1Zog2UTmcaXoHaDHXu9QqEm46t36kVSJsR5z+iKlJ9D4Iyx1HXtps0vbVxPLK83IEN9v684UNtbR8Sy9tKQO3o1n3i+nr51Bo8OUZspqmz84MpI7xl/hOU+n0UMTYCK5K6Op0j2uWLtpVqIj+amEoCcx9MRo5Ddsi1t634GLvU0nwes6ZYuUVPIek9c7ENEf4WX4rPKQ3qumBCb5A2lo15/V3x+e96nUrKB/5vmxE1lZHgjNaKMGYvjUGYlqb5YqE/3cAB94nY3ETAuig=="

        val expectedSignatureInput = "label=(\"host\")"

        assertEquals(expectedSignatureBase, signatureBase.generateSignatureBase(SignatureParameter()))
        assertEquals(expectedSignatureValue, sign.signature)
        assertEquals(expectedSignatureInput, sign.signatureInput)

        println(signatureBase.generateSignatureBase(SignatureParameter()))
        println(sign.signature)
        println(sign.signatureInput)
    }
}
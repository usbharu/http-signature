package dev.usbharu.httpsignature.sign

import dev.usbharu.httpsignature.common.HttpHeaders
import dev.usbharu.httpsignature.common.HttpMethod
import dev.usbharu.httpsignature.common.HttpRequest
import dev.usbharu.httpsignature.common.PrivateKey
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.mockito.MockSettings
import org.mockito.Mockito
import org.mockito.Mockito.*
import java.net.URL
import java.security.KeyFactory
import java.security.SignatureSpi
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.util.*

class Hs2019HttpSignatureSignerTest{
    @Test
    fun Hs2019で署名を作成できる() {
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

        val publicKey = Base64.getDecoder().decode(
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx/vCEUHQfb4Xo3jUKsMZ" +
                    "SLrbeF8Y4N3meV2JuyoEeIwE/6u/nH7M9v31UzcAzgaRth9WCWUS1LK1SNz4mvJO" +
                    "6BcnpmChFDepGioqDuQvYQdE2okxpcQCiO7Morb3nR9WLR6n+M76oLSNsi79DQF4" +
                    "2t51KFmVoGYPGVB1gBobR3fwaS4sr5cFwMnRR5f3jebvLgmYUA9GyiOSiaovFXLO" +
                    "fUNd/mTRxXYLzY3g/h3NgHTpmweR61tsERIHdbMoAXGe+7Ei8pXnnpfPnVZA7Kv5" +
                    "eDEFef9D3jp/jyPKSZMkFKapxMas5Lt+eF1vWROl40RIAW/TNABHcgS5OfmG2cIq" +
                    "qwIDAQAB"
        )

        val x509EncodedKeySpec = X509EncodedKeySpec(publicKey)
        val rsaPublicKey = KeyFactory.getInstance("RSA").generatePublic(x509EncodedKeySpec) as RSAPublicKey

        val rsaSha256HttpSignatureSigner = Hs2019HttpSignatureSigner(10L,0)
        val headers = HttpHeaders(
            mapOf(
                "X-Request-Id" to listOf("00000000-0000-0000-0000-000000000004"),
                "Tpp-Redirect-Uri" to listOf("https://www.sometpp.com/redirect/"),
                "Digest" to listOf("SHA-256=TGGHcPGLechhcNo4gndoKUvCBhWaQOPgtoVDIpxc6J4="),
                "Psu-Id" to listOf("1337")
            )
        )
        val httpRequest = HttpRequest(URL("https://example.com/"), headers, HttpMethod.GET)
        val signature = rsaSha256HttpSignatureSigner.sign(
            httpRequest, PrivateKey(rsaPrivateKey, "https://test-hideout.usbharu.dev/users/c#pubkey"),
            listOf("x-request-id", "tpp-redirect-uri", "digest", "psu-id")
        )

        assertEquals(
            "rvkWT/VgG5yVcr1D9bL3LB8Y2g6H92A3LoI8QomjbYOgJG5yLLz9dyE335pU7N2fXAbqBkEFssM77QGOx1Mp1XPUhgXO6SKu03B9ZtRdci1yBMovAd44sbDN3jt4sMSAO7nfeE1wvqJsf70bxXuc5bUat9ij8xNDA2G1W5xYV2uvSzdkeOlQd+LxfKfoLJEHwAeYMkKt2MPlDvVGJspkXh8OwIAFODXrY/k6BW1gaUTj+n9xoHrNQtFa3hTJGdDxF2Ntpn2W5Vt1Wg0hNK/fXK1pedCdyR6LgW9jyyeNamjsg36bbcyNYgS4b7L0vHXxvLaNXATojqmW43/UFF5BNA==",
            signature.signature
        )
    }

    @Test
    fun 特殊ヘッダーcreatedを指定したときに作成日時が追加される() {
        val ofEpochMilli = Instant.ofEpochSecond(1402170695)
        val instantMockedStatic = mockStatic(Instant::class.java)
        instantMockedStatic.`when`<Instant>(Instant::now).thenReturn(ofEpochMilli)

        val hs2019HttpSignatureSigner = Hs2019HttpSignatureSigner(10)
        val buildSignString = hs2019HttpSignatureSigner.buildSignString(
            URL("https://example.com"), HttpMethod.GET, HttpHeaders(mapOf()),
            listOf("(created)")
        )
        instantMockedStatic.close()
        assertEquals("(created): ${ofEpochMilli.epochSecond}",buildSignString)
    }

    @Test
    fun 特殊ヘッダーexpiresを指定したときに作成日時に指定時間を足したものが追加される() {
        val ofEpochSecond = Instant.ofEpochSecond(1402170695)

        val mock = spy(ofEpochSecond)
        val mockStatic = mockStatic(Instant::class.java,Mockito.CALLS_REAL_METHODS)
        mock.plusSeconds(10)
        mockStatic.`when`<Instant>(Instant::now).thenReturn(mock)


        mockStatic.use {

            val hs2019HttpSignatureSigner = Hs2019HttpSignatureSigner(10)
            val buildSignString = hs2019HttpSignatureSigner.buildSignString(
                URL("https://example.com"), HttpMethod.GET, HttpHeaders(mapOf()),
                listOf("(expires)")
            )
            assertEquals("(expires): ${ofEpochSecond.plusSeconds(10).epochSecond}",buildSignString)
        }

    }

    @Test
    fun 特殊ヘッダー付きのリクエストを署名できる() {

        val ofEpochSecond = Instant.ofEpochSecond(1402170695)
        val mockStatic = mockStatic(Instant::class.java, CALLS_REAL_METHODS)
        mockStatic.`when`<Instant>(Instant::now).thenReturn(ofEpochSecond)
        mockStatic.use {


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

            val publicKey = Base64.getDecoder().decode(
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx/vCEUHQfb4Xo3jUKsMZ" +
                        "SLrbeF8Y4N3meV2JuyoEeIwE/6u/nH7M9v31UzcAzgaRth9WCWUS1LK1SNz4mvJO" +
                        "6BcnpmChFDepGioqDuQvYQdE2okxpcQCiO7Morb3nR9WLR6n+M76oLSNsi79DQF4" +
                        "2t51KFmVoGYPGVB1gBobR3fwaS4sr5cFwMnRR5f3jebvLgmYUA9GyiOSiaovFXLO" +
                        "fUNd/mTRxXYLzY3g/h3NgHTpmweR61tsERIHdbMoAXGe+7Ei8pXnnpfPnVZA7Kv5" +
                        "eDEFef9D3jp/jyPKSZMkFKapxMas5Lt+eF1vWROl40RIAW/TNABHcgS5OfmG2cIq" +
                        "qwIDAQAB"
            )

            val x509EncodedKeySpec = X509EncodedKeySpec(publicKey)
            val rsaPublicKey = KeyFactory.getInstance("RSA").generatePublic(x509EncodedKeySpec) as RSAPublicKey

            val rsaSha256HttpSignatureSigner = Hs2019HttpSignatureSigner(10L, 0)
            val headers = HttpHeaders(
                mapOf(
                    "Digest" to listOf("SHA-256=TGGHcPGLechhcNo4gndoKUvCBhWaQOPgtoVDIpxc6J4="),
                )
            )
            val httpRequest = HttpRequest(URL("https://example.com/"), headers, HttpMethod.GET)
            val signature = rsaSha256HttpSignatureSigner.sign(
                httpRequest, PrivateKey(rsaPrivateKey, "https://test-hideout.usbharu.dev/users/c#pubkey"),
                listOf("(request-target)", "(created)", "(expires)", "digest")
            )

            assertEquals(
                "Tqise/VQjlrtI+JtXJgpWXkr5XkkW+sV2QM9GWJo2mKH3EWdVJe2nG9SyzG7BUejGqcJyluGFGTgdhzIpncEDozQDBa6A28n/d/BzuPAMPR2KU0LtGAprs6kir4MIMBA+22tnS3Jy/RQiie0C2EbNWidFDoRuKUBCu2NbfAtrWXpb0NJ7bHFDfW0klN80y7TFYSaZVtt8H9ge/IW+tF+q/6ey71djY9gR4ZyA2fDBW/XusBmtOc8OavRKO/VEXvEVSwTHHVyw4KAJ4z+7yP/ikU7id0/fmByr6oecNDZ7t986Ht4bLmpOPg2zefv8w69GwQK8lkoCi/8DkO8nG2JJg==",
                signature.signature
            )
            assertEquals("keyId=\"https://test-hideout.usbharu.dev/users/c#pubkey\",algorithm=\"hs2019\",created=\"1402170695\",expires=\"1402170705\",headers=\"(request-target) (created) (expires) digest\",signature=\"Tqise/VQjlrtI+JtXJgpWXkr5XkkW+sV2QM9GWJo2mKH3EWdVJe2nG9SyzG7BUejGqcJyluGFGTgdhzIpncEDozQDBa6A28n/d/BzuPAMPR2KU0LtGAprs6kir4MIMBA+22tnS3Jy/RQiie0C2EbNWidFDoRuKUBCu2NbfAtrWXpb0NJ7bHFDfW0klN80y7TFYSaZVtt8H9ge/IW+tF+q/6ey71djY9gR4ZyA2fDBW/XusBmtOc8OavRKO/VEXvEVSwTHHVyw4KAJ4z+7yP/ikU7id0/fmByr6oecNDZ7t986Ht4bLmpOPg2zefv8w69GwQK8lkoCi/8DkO8nG2JJg==\"", signature.signatureHeader)
        }
    }
}

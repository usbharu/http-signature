package dev.usbharu.httpsignature.v2

import dev.usbharu.httpsignature.common.SignatureBaseBuilder
import dev.usbharu.httpsignature.common.SignatureParameters
import dev.usbharu.httpsignature.sign.HttpMessageSignatureSigner
import dev.usbharu.httpsignature.sign.Material
import dev.usbharu.httpsignature.sign.RsaPssSha512SignatureSigner
import dev.usbharu.httpsignature.sign.RsaV1_5Sha256SignatureSigner
import dev.usbharu.httpsignature.verify.HttpMessageSignatureVerifier
import dev.usbharu.httpsignature.verify.RsaPssSha512SignatureVerifier
import dev.usbharu.httpsignature.verify.RsaV1_5Sha256SignatureVerifier
import dev.usbharu.httpsignature.verify.VerifyMaterial
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.KeyFactory
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.util.*

class HttpMessageSignatureVerifierTest {

    @Test
    fun verify() {
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

        val signatureBase = SignatureBaseBuilder()
            .header("Host", "example.com")
            .build()

        val material = Material(
            signatureBase,
            rsaPrivateKey,
            "label"
        )

        val signer = HttpMessageSignatureSigner()

        val sign = signer.sign(material, SignatureParameters().toParameterList(), RsaV1_5Sha256SignatureSigner())

        val httpMessageSignatureVerifier = HttpMessageSignatureVerifier()

        val actual = httpMessageSignatureVerifier.verify(
            VerifyMaterial(
                signatureBase, rsaPublicKey, "label"
            ),
            sign, RsaV1_5Sha256SignatureVerifier()
        )

        assertTrue(actual)
    }

    @Test
    fun verify2() {
        val key = KeyFactory.getInstance("RSASSA-PSS").generatePrivate(
            PKCS8EncodedKeySpec(
                Base64.getDecoder().decode(
                    "MIIEvgIBADALBgkqhkiG9w0BAQoEggSqMIIEpgIBAAKCAQEAr4tmm3r20Wd/Pbqv" +
                            "P1s2+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry5" +
                            "3mm+oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7Oyr" +
                            "FAHqgDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUA" +
                            "AN5WUtzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw" +
                            "9lq4aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oy" +
                            "c6XI2wIDAQABAoIBAQCUB8ip+kJiiZVKF8AqfB/aUP0jTAqOQewK1kKJ/iQCXBCq" +
                            "pbo360gvdt05H5VZ/RDVkEgO2k73VSsbulqezKs8RFs2tEmU+JgTI9MeQJPWcP6X" +
                            "aKy6LIYs0E2cWgp8GADgoBs8llBq0UhX0KffglIeek3n7Z6Gt4YFge2TAcW2WbN4" +
                            "XfK7lupFyo6HHyWRiYHMMARQXLJeOSdTn5aMBP0PO4bQyk5ORxTUSeOciPJUFktQ" +
                            "HkvGbym7KryEfwH8Tks0L7WhzyP60PL3xS9FNOJi9m+zztwYIXGDQuKM2GDsITeD" +
                            "2mI2oHoPMyAD0wdI7BwSVW18p1h+jgfc4dlexKYRAoGBAOVfuiEiOchGghV5vn5N" +
                            "RDNscAFnpHj1QgMr6/UG05RTgmcLfVsI1I4bSkbrIuVKviGGf7atlkROALOG/xRx" +
                            "DLadgBEeNyHL5lz6ihQaFJLVQ0u3U4SB67J0YtVO3R6lXcIjBDHuY8SjYJ7Ci6Z6" +
                            "vuDcoaEujnlrtUhaMxvSfcUJAoGBAMPsCHXte1uWNAqYad2WdLjPDlKtQJK1diCm" +
                            "rqmB2g8QE99hDOHItjDBEdpyFBKOIP+NpVtM2KLhRajjcL9Ph8jrID6XUqikQuVi" +
                            "4J9FV2m42jXMuioTT13idAILanYg8D3idvy/3isDVkON0X3UAVKrgMEne0hJpkPL" +
                            "FYqgetvDAoGBAKLQ6JZMbSe0pPIJkSamQhsehgL5Rs51iX4m1z7+sYFAJfhvN3Q/" +
                            "OGIHDRp6HjMUcxHpHw7U+S1TETxePwKLnLKj6hw8jnX2/nZRgWHzgVcY+sPsReRx" +
                            "NJVf+Cfh6yOtznfX00p+JWOXdSY8glSSHJwRAMog+hFGW1AYdt7w80XBAoGBAImR" +
                            "NUugqapgaEA8TrFxkJmngXYaAqpA0iYRA7kv3S4QavPBUGtFJHBNULzitydkNtVZ" +
                            "3w6hgce0h9YThTo/nKc+OZDZbgfN9s7cQ75x0PQCAO4fx2P91Q+mDzDUVTeG30mE" +
                            "t2m3S0dGe47JiJxifV9P3wNBNrZGSIF3mrORBVNDAoGBAI0QKn2Iv7Sgo4T/XjND" +
                            "dl2kZTXqGAk8dOhpUiw/HdM3OGWbhHj2NdCzBliOmPyQtAr770GITWvbAI+IRYyF" +
                            "S7Fnk6ZVVVHsxjtaHy1uJGFlaZzKR4AGNaUTOJMs6NadzCmGPAxNQQOCqoUjn4XR" +
                            "rOjr9w349JooGXhOxbu8nOxX"
                )
            )
        )

        val signer = HttpMessageSignatureSigner()
        val signatureBase = SignatureBaseBuilder()
            .header("Host", "example.com")
            .build()
        val material = Material(
            signatureBase,
            key,
            "sig"
        )

        val signatureParameters = SignatureParameters(
            algorithm = "rsa-pss-sha512",
            keyId = "a",
            created = Instant.ofEpochSecond(1727076643),
//            expires = Instant.ofEpochSecond(1727076943),
            nonce = "a",
            tag = "a"
        )
        val sign = signer.sign(
            material,
            signatureParameters.toParameterList(),
            RsaPssSha512SignatureSigner()
        )

        val publicKey = KeyFactory.getInstance("RSA").generatePublic(
            X509EncodedKeySpec(
                Base64.getDecoder().decode(
                    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2" +
                            "+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+" +
                            "oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHq" +
                            "gDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5W" +
                            "Utzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4" +
                            "aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI" +
                            "2wIDAQAB"
                )
            )
        )

        HttpMessageSignatureVerifier().verify(
            VerifyMaterial(signatureBase, publicKey, "sig"),
            sign,
            RsaPssSha512SignatureVerifier()
        )

    }
}
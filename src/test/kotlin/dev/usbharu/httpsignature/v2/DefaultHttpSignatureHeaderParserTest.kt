package dev.usbharu.httpsignature.v2

import org.junit.jupiter.api.Test

class DefaultHttpSignatureHeaderParserTest {
    @Test
    fun name() {
        val defaultHttpSignatureHeaderParser = DefaultHttpSignatureHeaderParser()
        defaultHttpSignatureHeaderParser.parse(
            listOf(
                "sig1=(\"@method\" \"@target-uri\" \"@authority\" " +
                        "     \"content-digest\" \"cache-control\");" +
                        "     created=1618884475;keyid=\"test-key-rsa-pss\""
            ), listOf()
        )
    }

    @Test
    fun test2() {
        val parse = DefaultHttpSignatureHeaderParser().parse(
            listOf(
                "sig1=(\"@method\" \"@authority\" \"@path\" " +
                        "\"content-digest\" \"content-type\" \"content-length\")" +
                        ";created=1618884475;keyid=\"test-key-ecc-p256\", " +
                        "proxy_sig=(\"@method\" \"@authority\" \"@path\" \"content-digest\" " +
                        "\"content-type\" \"content-length\" \"forwarded\")" +
                        ";created=1618884480;keyid=\"test-key-rsa\";alg=\"rsa-v1_5-sha256\"" +
                        ";expires=1618884540"
            ), listOf(
                "sig1=:X5spyd6CFnAG5QnDyHfqoSNICd+BUP4LYMz2Q0JXlb//4Ijpzp" +
                        "+kve2w4NIyqeAuM7jTDX+sNalzA8ESSaHD3A==:, " +
                        "proxy_sig=:S6ZzPXSdAMOPjN/6KXfXWNO/f7V6cHm7BXYUh3YD/fRad4BCaRZxP+" +
                        "JH+8XY1I6+8Cy+CM5g92iHgxtRPz+MjniOaYmdkDcnL9cCpXJleXsOckpURl49G" +
                        "wiyUpZ10KHgOEe11sx3G2gxI8S0jnxQB+Pu68U9vVcasqOWAEObtNKKZd8tSFu7" +
                        "LB5YAv0RAGhB8tmpv7sFnIm9y+7X5kXQfi8NMaZaA8i2ZHwpBdg7a6CMfwnnrtf" +
                        "lzvZdXAsD3LH2TwevU+/PBPv0B6NMNk93wUs/vfJvye+YuI87HU38lZHowtznbL" +
                        "Vdp770I6VHR6WfgS9ddzirrswsE1w5o0LV/g==:"
            )
        )

        println(parse)
    }
}
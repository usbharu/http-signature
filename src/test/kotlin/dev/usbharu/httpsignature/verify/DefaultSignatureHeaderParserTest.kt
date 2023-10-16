package dev.usbharu.httpsignature.verify

import dev.usbharu.httpsignature.common.HttpHeaders
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class DefaultSignatureHeaderParserTest{
    @Test
    fun 必要なヘッダーが全て揃っているリクエストをパースできる() {
        val defaultSignatureHeaderParser = DefaultSignatureHeaderParser()

        val signature =
            defaultSignatureHeaderParser.parse(HttpHeaders(mapOf("Signature" to listOf("keyId=\"https://test-hideout.usbharu.dev/users/c#pubkey\", algorithm=\"rsa-sha256\", headers=\"x-request-id tpp-redirect-uri digest psu-id\", signature=\"FfpkmBogW70FMo94yovGpl15L/m4bDjVIFb9mSZUstPE3H00nHiqNsjAq671qFMJsGOO1uWfLEExcdvzwTiC3wuHShzingvxQUbTgcgRTRZcHbtrOZxT8hYHGndpCXGv/NOLkfXDtZO9v5u0fnA2yJFokzyPHOPJ1cJliWlXP38Bl/pO4H5rBLQBZKpM2jYIjMyI78G2rDXNHEeGrGiyfB5SKb3H6zFQL+X9QpXUI4n0f07VsnwaDyp63oUopmzNUyBEuSqB+8va/lbfcWwrxpZnKGzQRZ+VBcV7jDoKGNOP9/O1xEI2CwB8sh+h6KVHdX3EQEvO1slaaLzcwRRqrQ==\""))))

        val expacted = Signature(
            "https://test-hideout.usbharu.dev/users/c#pubkey",
            "rsa-sha256",
            listOf("x-request-id","tpp-redirect-uri","digest","psu-id"),
            "FfpkmBogW70FMo94yovGpl15L/m4bDjVIFb9mSZUstPE3H00nHiqNsjAq671qFMJsGOO1uWfLEExcdvzwTiC3wuHShzingvxQUbTgcgRTRZcHbtrOZxT8hYHGndpCXGv/NOLkfXDtZO9v5u0fnA2yJFokzyPHOPJ1cJliWlXP38Bl/pO4H5rBLQBZKpM2jYIjMyI78G2rDXNHEeGrGiyfB5SKb3H6zFQL+X9QpXUI4n0f07VsnwaDyp63oUopmzNUyBEuSqB+8va/lbfcWwrxpZnKGzQRZ+VBcV7jDoKGNOP9/O1xEI2CwB8sh+h6KVHdX3EQEvO1slaaLzcwRRqrQ=="
        )
        assertEquals(expacted,signature)
    }

    @Test
    fun Signatureヘッダーに不要なパラメーターが入っていてもパースできる() {
        val defaultSignatureHeaderParser = DefaultSignatureHeaderParser()

        val signature =
            defaultSignatureHeaderParser.parse(HttpHeaders(mapOf("Signature" to listOf("Signature keyId=\"https://test-hideout.usbharu.dev/users/c#pubkey\", algorithm=\"rsa-sha256\", headers=\"x-request-id tpp-redirect-uri digest psu-id\", signature=\"tQs/l4DwlbcZ3GOA4IrCB5vSAt5J6pxonzsCg2inPY7O+Nlc3Hk/z559+kyy6CFVpmW+PzzCMzQPVgZUdfTDnRXCAhlgSBRNl88UCkkS34kiq8i0nCd+erVRUZ3wI3ttqEdOxoJWU+l4jKm/C70m8XHhrtVlvUBk6jhdQP27+zrHawORq/Oxxmj5o3K5gqNMyrgXoEp5MCrswju/tzJl1i1w0ppGtQk93syqFdJpPp1dKUyeE0HxcCl8EBVMojZNR0uWpT/ACInaRM988ZMFU7JEKZ8BeuWkiDNA5Gk8J3Gal2z/hAn6pzLI4YiQ+7iH5QHzoB3RMASprl5wb3OQsQ==\""))))

        val expacted = Signature(
            "https://test-hideout.usbharu.dev/users/c#pubkey",
            "rsa-sha256",
            listOf("x-request-id","tpp-redirect-uri","digest","psu-id"),
            "tQs/l4DwlbcZ3GOA4IrCB5vSAt5J6pxonzsCg2inPY7O+Nlc3Hk/z559+kyy6CFVpmW+PzzCMzQPVgZUdfTDnRXCAhlgSBRNl88UCkkS34kiq8i0nCd+erVRUZ3wI3ttqEdOxoJWU+l4jKm/C70m8XHhrtVlvUBk6jhdQP27+zrHawORq/Oxxmj5o3K5gqNMyrgXoEp5MCrswju/tzJl1i1w0ppGtQk93syqFdJpPp1dKUyeE0HxcCl8EBVMojZNR0uWpT/ACInaRM988ZMFU7JEKZ8BeuWkiDNA5Gk8J3Gal2z/hAn6pzLI4YiQ+7iH5QHzoB3RMASprl5wb3OQsQ=="
        )
        assertEquals(expacted,signature)
    }
}

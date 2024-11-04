package com.bosa.signandvalidation;

import com.bosa.signandvalidation.exceptions.Utils;
import com.bosa.signandvalidation.model.TrustSources;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static com.bosa.signandvalidation.exceptions.Utils.getGetExtraTrustFile;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class UtilsTest {
    @Test
    public void testSantize() throws IllegalAccessException {
        assertEquals("ValidString", Utils.sanitize("ValidString", 100));

        assertEquals("Valid", Utils.sanitize("ValidString", 5));

        assertEquals("#nvalidString", Utils.sanitize("ünvalidString", 100));

        assertEquals("#nval", Utils.sanitize("ünvalidString", 5));
    }

    @Test
    public void testTrust() throws IllegalAccessException, IOException {

        TrustSources trust = getGetExtraTrustFile("SPFJusticeSepia.crt");

        assertEquals(trust.getCerts().size(), 1);
        assertEquals(trust.getCerts().get(0).length, 1606);
    }
}

package com.bosa.signandvalidation;

import com.bosa.signandvalidation.exceptions.Utils;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class UtilsTest {
    @Test
    public void testSantize() throws IllegalAccessException {
        assertEquals("ValidString", Utils.sanitize("ValidString", 100));

        assertEquals("Valid", Utils.sanitize("ValidString", 5));

        assertEquals("#nvalidString", Utils.sanitize("ünvalidString", 100));

        assertEquals("#nval", Utils.sanitize("ünvalidString", 5));
    }
}

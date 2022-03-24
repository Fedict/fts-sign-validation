package com.bosa.signandvalidation.service;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.Calendar;

@SpringBootTest
@ActiveProfiles("localh2")
public class BosaRemoteDocumentValidationServiceTest {
    @Test
    public void testSigWasJustMade() throws Exception {
	Calendar cal = Calendar.getInstance();

	assertTrue(BosaRemoteDocumentValidationService.sigWasJustMade(cal.getTime())); // now

	cal.add(Calendar.SECOND, -4); // 4 seconds ago
	assertTrue(BosaRemoteDocumentValidationService.sigWasJustMade(cal.getTime()));

	cal.add(Calendar.SECOND, -7); // 11 seconds ago -> too long
	assertFalse(BosaRemoteDocumentValidationService.sigWasJustMade(cal.getTime()));
    }
}

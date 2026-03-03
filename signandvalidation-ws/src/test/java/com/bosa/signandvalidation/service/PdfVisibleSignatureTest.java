package com.bosa.signandvalidation.service;

import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureFieldParameters;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

import java.io.File;
import java.io.IOException;
import java.util.Date;
import java.util.LinkedHashMap;

import static com.bosa.signandvalidation.service.PdfVisibleSignatureServiceTest.RESOURCE_PATH;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

public class PdfVisibleSignatureTest {
    @BeforeAll
    public static void init() throws IOException {
        PdfVisibleSignatureServiceTest.clearList();
    }
    @AfterAll
    public static void out() throws IOException {
        PdfVisibleSignatureServiceTest.printNewPdfSignatureFiles();
    }

    @Test
    public void testMakeText() throws Exception {
        LinkedHashMap<String,String> texts = new LinkedHashMap<String,String>();
        texts.put("en", "Signed by %gn% %sn% (%nn%=%rrn%)\non %d(MMM d YYYY)%");
        texts.put("nl", "Getekend door %gn% %sn% (%nn%=%rrn%)\nop %d(d MMM YYYY)%");
        texts.put("fr", "Signé par %gn% %sn% (%nn%=%rrn%)\nau %d(d MMM YYYY)%");
        texts.put("de", "Unterzeichnet von %gn% %sn% (%nn%=%rrn%)\nam %d(d MMM YYYY)%");
        texts.put("mu", "Signed, Getekend, Signé, Unterzeichnet %gn% %sn% (%nn%=%rrn%)\n%d(d MMM YYYY)%");

        Date signingDate = new Date();
        signingDate.setTime(1623318619435L);

        RemoteCertificate signingCert = CertInfoTest.getTomTestCertificate();

        String text = PdfVisibleSignatureService.makeText(null, null, signingDate, signingCert);
        assertEquals("Tom Test", text);
        text = PdfVisibleSignatureService.makeText(texts, null, signingDate, signingCert);
        assertEquals("Signed by Tom Test (73040102749=73040102749)\non Jun 10 2021", text);
        text = PdfVisibleSignatureService.makeText(texts, "en", signingDate, signingCert);
        assertEquals("Signed by Tom Test (73040102749=73040102749)\non Jun 10 2021", text);
        text = PdfVisibleSignatureService.makeText(texts, "nl", signingDate, signingCert);
        // Ignore minor "locale" differences for date formatting (Ideally we should change the locale in the main code but there is a risk of PRD regression)
        text = text.replaceAll(" jun\\. ", " jun ");
        assertEquals("Getekend door Tom Test (73040102749=73040102749)\nop 10 jun 2021", text);
        text = PdfVisibleSignatureService.makeText(texts, "fr", signingDate, signingCert);
        assertEquals("Signé par Tom Test (73040102749=73040102749)\nau 10 juin 2021", text);
        text = PdfVisibleSignatureService.makeText(texts, "mu", signingDate, signingCert);
        assertEquals("Signed, Getekend, Signé, Unterzeichnet Tom Test (73040102749=73040102749)\n10 Jun 2021", text);
        text = PdfVisibleSignatureService.makeText(texts, "de", signingDate, signingCert);
        // Ignore minor "locale" differences for date formatting (Ideally we should change the locale in the main code but there is a risk of PRD regression)
        text = text.replaceAll(" Juni ", " Jun ");
        assertEquals("Unterzeichnet von Tom Test (73040102749=73040102749)\nam 10 Jun 2021", text);
        try {
            PdfVisibleSignatureService.makeText(texts, "xx", signingDate, signingCert);
            fail(); // we shouldn't get here
        } catch (ResponseStatusException e) {
            assertEquals("403 FORBIDDEN \"NOW||INVALID_PARAM||language 'xx' not specified in the psp file\"", e.getMessage().replaceAll("\\d{17}", "NOW"));
        }

        texts = new LinkedHashMap<String,String>();
        texts.put("en", "%d(MMM d YYYY)% %d(yyyy.MMMMM.dd)%");
        text = PdfVisibleSignatureService.makeText(texts, null, signingDate, signingCert);
        assertEquals("Jun 10 2021 2021.June.10", text);
    }

    @Test
    public void testRemoteSignSignature() throws Exception {

        testRender("normal", 496, 264, "Date of signature", "The 24th of June 2024 by", "Simon", "Du lion");

        testRender("small", 248, 132, "Date of signature", "The 24th of June 2024 by", "Jos", "Vandekasteel");

        testRender("longNames", 600, 132, "Date of signature", "The 10th of June 2024 at 10h30 UTC", "VerylongFirstNamePerson", "VerylongLastNamePerson");

        testRender("veryLongNames", 620, 330, "Date of signature", "The 10th of June 2024 at 10h30 UTC with a crazy length", "VerylongFirstNamePerson with a crazy length", "VerylongLastNamePerson with a crazy length");

        testRender("high", 150, 200, "Date of signature", "The 24th of June 2024 by", "Zaphod", "Beeblebrox");

        testRender("highLarge", 300, 600, "Date of signature", "The 24th of June 2024 by", "", "Marvin");

        testRender("smallName",140, 200, "Date of signature", "The 24th of June 2024 by", "Arthur", "Dent");

        testRender("micro",50, 30, "Date of signature", "The 24th of June 2024 by", "Arthur", "Dent");
    }
    
    private static void testRender(String targetImage, float x, float y, String date1, String date2, String firstNames, String lastName) throws Exception {
        File testFolder = new File(RESOURCE_PATH, "VisibleSignatures");
        RemoteSignatureFieldParameters fb = new RemoteSignatureFieldParameters();
        fb.setWidth(x);
        fb.setHeight(y);
        byte[] rawPngImage = PdfImageBuilder.makeRemoteSignPdfImage(fb, date1 + "\n" + date2 + "\n" + firstNames + "\n" + lastName);
        PdfVisibleSignatureServiceTest.compareImages(testFolder, rawPngImage, targetImage);
    }
}

package com.bosa.signandvalidation.controller;

import com.bosa.signandvalidation.model.*;
import com.bosa.signingconfigurator.model.PolicyParameters;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;

public class SigningControllerInputCheckTest {

    private static SigningController ctrl = new SigningController();
    private static String EMPTY_PARAM = "||EMPTY_PARAM||";

    @Test
    public void testNoSignProfile() throws Exception {
        TokenObject token = new TokenObject();
        testToken(token, EMPTY_PARAM + "signProfile is null");
    }

    @Test
    public void testNullPolicyId() throws Exception {
        TokenObject token = new TokenObject();
        token.setSignProfile("Profile");
        token.setPolicy(new PolicyParameters());
        testToken(token, EMPTY_PARAM + "policyId is null");
    }

    @Test
    public void testMaxSignTimeout() throws Exception {
        TokenObject token = new TokenObject();
        token.setSignProfile("Profile");
        token.setSignTimeout(100000);
        testToken(token, "||SIGN_PERIOD_EXPIRED||signTimeout (100000) can't be larger than TOKEN_VALIDITY_SECS (18000)");
    }

    @Test
    public void testNNAllowedToSignErrors() throws Exception {
        TokenObject token = new TokenObject();
        token.setSignProfile("Profile");
        int count = 100;
        List<String> nnAllowedToSign = new ArrayList<String>(count);
        while (count != 0) nnAllowedToSign.add(Integer.toString(--count));
        token.setNnAllowedToSign(nnAllowedToSign);
        testToken(token, EMPTY_PARAM + "nnAllowedToSign (100) can't be larger than MAX_NN_ALLOWED_TO_SIGN (32)");

        token.setNnAllowedToSign(Arrays.asList(new String[]{"112312312313131"}));
        testToken(token, EMPTY_PARAM + "'nnAllowedToSign' (112312312313131) does not match Regex ([0-9]{11})");

        token.setNnAllowedToSign(Arrays.asList(new String[]{"01234567890", "01234567890"}));
        testToken(token, EMPTY_PARAM + "'nnAllowedToSign' (01234567890) is not unique");
    }

    @Test
    public void testInputsErrors() throws Exception {
        // Check general input
        TokenObject token = new TokenObject();
        token.setSignProfile("Profile");
        testToken(token, EMPTY_PARAM + "'inputs' field is empty");

        List<TokenSignInput> inputs = new ArrayList<>();
        token.setInputs(inputs);
        testToken(token, EMPTY_PARAM + "'inputs' field is empty");

        // Check files input, first with "single file, non Xades"
        TokenSignInput input = new TokenSignInput();
        input.setFilePath("file1.pdf");
        input.setXmlEltId("#234234");
        inputs.add(input);
        testToken(token, EMPTY_PARAM + "'XmlEltId' must be null for 'non Xades Multifile'");
        input.setXmlEltId(null);

        input.setSignLanguage("ch");
        testToken(token, EMPTY_PARAM + "'SignLanguage' (ch) must be one of fr, de, nl, en");
        input.setSignLanguage("fr");

        input.setDisplayXsltPath("xslt");
        testToken(token, EMPTY_PARAM + "DisplayXslt must be null for non-xml files");
        input.setDisplayXsltPath(null);

        token.setOutXsltPath("file2.xml");
        testToken(token, EMPTY_PARAM + "'OutXslt' must be null for 'non Xades Multifile'");

        // ... then check "Xades multifile", first with one file
        token.setXadesMultifile(true);
        testToken(token, EMPTY_PARAM + "'XmlEltId' is NULL");

        input.setXmlEltId("#234234");
        testToken(token, EMPTY_PARAM + "'XmlEltId' (#234234) does not match Regex ([a-zA-Z0-9\\-_]{1,30})");
        input.setXmlEltId("ID1");

        testToken(token, EMPTY_PARAM + "PsfN, PsfC, SignLanguage and PspFileName must be null for Multifile Xades");
        input.setSignLanguage(null);

        input.setPsfN("xxxx");
        testToken(token, EMPTY_PARAM + "PsfN, PsfC, SignLanguage and PspFileName must be null for Multifile Xades");
        input.setPsfN(null);

        input.setPsfC("xxxx");
        testToken(token, EMPTY_PARAM + "PsfN, PsfC, SignLanguage and PspFileName must be null for Multifile Xades");
        input.setPsfN(null);

        input.setPsfC("xxxx");
        testToken(token, EMPTY_PARAM + "PsfN, PsfC, SignLanguage and PspFileName must be null for Multifile Xades");
        input.setPsfC(null);

        input.setPspFilePath("pspFN");
        testToken(token, EMPTY_PARAM + "PsfN, PsfC, SignLanguage and PspFileName must be null for Multifile Xades");
        input.setPspFilePath(null);

        // ... then with two files
        TokenSignInput input2 = new TokenSignInput();
        input2.setFilePath("file1.pdf");
        input2.setXmlEltId("ID1");
        inputs.add(input2);
        testToken(token, EMPTY_PARAM + "'fileName' (file1.pdf) is not unique");

        input2.setFilePath(null);
        testToken(token, EMPTY_PARAM + "'fileName' is NULL");

        input2.setFilePath("file2.xml");
        testToken(token, EMPTY_PARAM + "'XmlEltId' (ID1) is not unique");
        input2.setXmlEltId("ID2");
        input2.setDisplayXsltPath("xslt");

        // finish with general params
        testToken(token, EMPTY_PARAM + "'OutXslt' (file2.xml) is not unique");
        token.setOutXsltPath("OutXSLT.xml");

        token.setOutFilePath("file2.xml");
        testToken(token, EMPTY_PARAM + "'outFileName' (file2.xml) is not unique");
    }

    private void testToken(TokenObject token, String s) {
        Exception exception = assertThrows(ResponseStatusException.class, () -> {
            ctrl.checkToken(token);
        });
        assertTrue(exception.getMessage().contains(s));
    }
}

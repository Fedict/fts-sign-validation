package com.bosa.signandvalidation.controller;

import com.bosa.signandvalidation.model.*;
import com.bosa.signingconfigurator.model.PolicyParameters;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ResponseStatusException;

import java.util.*;

import static com.bosa.signandvalidation.config.ErrorStrings.*;
import static org.junit.jupiter.api.Assertions.*;

public class SigningControllerInputCheckTest {

    private static SigningController ctrl = new SigningController();

    @BeforeAll
    static void init() {
        ReflectionTestUtils.setField(ctrl, "defaultTokenTimeout", (Integer)300);
    }

    @Test
    public void testNoSignProfile() throws Exception {
        TokenObject token = new TokenObject();
        testToken(token, EMPTY_PARAM, "signProfile and altSignProfile can't both be null.");
    }

    @Test
    public void testNullPolicyId() throws Exception {
        TokenObject token = new TokenObject();
        token.setPdfSignProfile("Profile");
        PolicyParameters policyParams = new PolicyParameters();
        token.setPolicy(policyParams);
        testToken(token, EMPTY_PARAM, "policyId is null");

        policyParams.setPolicyId("ID");
        testToken(token, EMPTY_PARAM, "'inputs' field is empty");
        assertEquals(DigestAlgorithm.SHA256, policyParams.getPolicyDigestAlgorithm());
    }

    @Test
    public void testMaxSignTimeout() throws Exception {
        TokenObject token = new TokenObject();
        token.setPdfSignProfile("Profile");
        token.setSignTimeout(100000);
        testToken(token, SIGN_PERIOD_EXPIRED, "signTimeout (100000) can't be larger than  Token expiration (18000)");
    }

    @Test
    public void testNNAllowedToSignErrors() throws Exception {
        TokenObject token = new TokenObject();
        token.setPdfSignProfile("Profile");
        int count = 100;
        List<String> nnAllowedToSign = new ArrayList<String>(count);
        while (count != 0) nnAllowedToSign.add(Integer.toString(--count));
        token.setNnAllowedToSign(nnAllowedToSign);
        testToken(token, INVALID_PARAM, "nnAllowedToSign (100) can't be larger than MAX_NN_ALLOWED_TO_SIGN (32)");

        token.setNnAllowedToSign(Arrays.asList(new String[]{"112312312313131"}));
        testToken(token, INVALID_PARAM, "'nnAllowedToSign' (112312312313131) does not match Regex ([0-9]{11})");

        token.setNnAllowedToSign(Arrays.asList(new String[]{"01234567890", "01234567890"}));
        testToken(token, INVALID_PARAM, "'nnAllowedToSign' (01234567890) is not unique");
    }

    @Test
    public void testInputsErrors() throws Exception {
        // Check general input
        TokenObject token = new TokenObject();
        token.setSigningType(SigningType.Standard);
        token.setPdfSignProfile("XADES_B");
        testToken(token, EMPTY_PARAM, "'inputs' field is empty");

        List<TokenSignInput> inputs = new ArrayList<>();
        token.setInputs(inputs);
        testToken(token, EMPTY_PARAM, "'inputs' field is empty");

        // Check files input, first with "single file, non Xades"
        TokenSignInput input = new TokenSignInput();
        input.setFilePath("file1.bin");
        inputs.add(input);
        testToken(token, INVALID_PARAM, "input files must be either XML or PDF");

        input.setFilePath("file1.xml");
        testToken(token, INVALID_PARAM, "No signProfile for file type provided (application/xml => XADES_B/null)");

        input.setFilePath("file1.pdf");
        input.setXmlEltId("#234234");
        testToken(token, INVALID_PARAM, "'XmlEltId' must be null for Standard");
        input.setXmlEltId(null);

        input.setSignLanguage("ch");
        testToken(token, INVALID_PARAM, "'SignLanguage' (ch) must be one of fr, de, nl, en");
        input.setSignLanguage("fr");

        input.setDisplayXsltPath("xslt");
        testToken(token, INVALID_PARAM, "DisplayXslt must be null for non-xml files");
        input.setDisplayXsltPath(null);

        token.setOutXsltPath("file2.xml");
        testToken(token, INVALID_PARAM, "'outXsltPath' must be null for Standard");

        // ... then check "Xades multifile", first with one file
        token.setSigningType(SigningType.XadesMultiFile);
        testToken(token, EMPTY_PARAM, "'XmlEltId' is NULL");

        input.setXmlEltId("#234234");
        testToken(token, INVALID_PARAM, "'XmlEltId' (#234234) does not match Regex ([a-zA-Z0-9\\-_]{1,30})");
        input.setXmlEltId("ID1");

        testToken(token, INVALID_PARAM, "PsfN, PsfC, SignLanguage and PspFileName must be null for XadesMultiFile");
        input.setSignLanguage(null);

        input.setPsfN("xxxx");
        testToken(token, INVALID_PARAM, "PsfN, PsfC, SignLanguage and PspFileName must be null for XadesMultiFile");
        input.setPsfN(null);

        input.setPsfC("xxxx");
        testToken(token, INVALID_PARAM, "PsfN, PsfC, SignLanguage and PspFileName must be null for XadesMultiFile");
        input.setPsfN(null);

        input.setPsfC("xxxx");
        testToken(token, INVALID_PARAM, "PsfN, PsfC, SignLanguage and PspFileName must be null for XadesMultiFile");
        input.setPsfC(null);

        input.setPspFilePath("pspFN");
        testToken(token, INVALID_PARAM, "PsfN, PsfC, SignLanguage and PspFileName must be null for XadesMultiFile");
        input.setPspFilePath(null);

        // ... then with two files
        TokenSignInput input2 = new TokenSignInput();
        input2.setFilePath("file1.pdf");
        input2.setXmlEltId("ID1");
        inputs.add(input2);
        testToken(token, INVALID_PARAM, "'fileName' (file1.pdf) is not unique");

        input2.setFilePath(null);
        testToken(token, EMPTY_PARAM, "'fileName' is NULL");

        input2.setFilePath("file2.xml");
        testToken(token, INVALID_PARAM, "'XmlEltId' (ID1) is not unique");
        input2.setXmlEltId("ID2");
        input2.setDisplayXsltPath("xslt");

        // finish with general params
        token.setXmlSignProfile("XADES_MDOC_LTA");
        testToken(token, INVALID_PARAM, "XadesMultiFile must be used only for XML files");
        token.setPdfSignProfile(null);

        testToken(token, INVALID_PARAM, "'outXsltPath' (file2.xml) is not unique");
        token.setOutXsltPath("OutXSLT.xml");

        token.setOutPathPrefix("ABC/");
        testToken(token, INVALID_PARAM, "'outPathPrefix' must be null for XadesMultiFile");

        token.setOutFilePath("file2.xml");
        token.setOutPathPrefix("ABC_");
        testToken(token, INVALID_PARAM, "'outPathPrefix' must be null for XadesMultiFile");

        token.setOutPathPrefix(null);
        testToken(token, INVALID_PARAM, "'outFilePath' (file2.xml) is not unique");
    }

    private void testToken(TokenObject token, String error, String s) {
        Exception exception = assertThrows(ResponseStatusException.class, () -> {
            ctrl.validateTokenValues(token);
        });
        boolean verified = exception.getMessage().contains("||" + error + "||" + s);
        if (!verified) {
            System.out.println("Exception :" + exception.getMessage() + " does not contain :" + s);
        }
        assertTrue(verified);
    }
}

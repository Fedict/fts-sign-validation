package com.bosa.signandvalidation.service;

import java.io.*;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.logging.Logger;

import com.bosa.signandvalidation.config.ThreadedCertificateVerifier;
import com.bosa.signandvalidation.model.SignatureFullValiationDTO;
import com.bosa.signandvalidation.model.TrustSources;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.simplereport.jaxb.*;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import eu.europa.esig.dss.ws.validation.dto.DataToValidateDTO;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlBasicSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import static com.bosa.signandvalidation.config.ErrorStrings.INVALID_PARAM;
import static com.bosa.signandvalidation.exceptions.Utils.logAndThrowEx;
import static org.springframework.http.HttpStatus.BAD_REQUEST;

/**
 * This validation service calls the DSS validation service and then applies some extra checks.
 */
@Configuration
public class BosaRemoteDocumentValidationService {

	// "cn=belgium root ca,c=be"
	private static final BigInteger BRCA = new BigInteger("580b056c5324dbb25057185ff9e5a650", 16);
	// "cn=belgium root ca2,c=be"
	private static final BigInteger BRCA2 = new BigInteger("2affbe9fa2f0e987", 16);
	// "cn=belgium root ca3,c=be"
	private static final BigInteger BRCA3 = new BigInteger("3b2102de965b1da9", 16);
	// "cn=belgium root ca4,c=be"
	private static final BigInteger BRCA4 = new BigInteger("4f33208cc594bf38", 16);
	// "cn=belgium root caA6 ou=fps policy and support - bosa (ntrbe-0671516647) ou=fps home affairs - bik-gci (ntbre-0362475538) o=kingdom of belgium - federal government l=brussels  c=be"
	private static final BigInteger BRCA6 = new BigInteger("718b57ff6b693e5a1c235ed887a3ef51f4010f26", 16);

	@Value("${test.rootCertSN:#{null}}")
	BigInteger testRootCertSN;

	private static final Logger logger = Logger.getLogger(BosaRemoteDocumentValidationService.class.getName());
	private ShadowRemoteDocumentValidationService remoteDocumentValidationService;

	public BosaRemoteDocumentValidationService() {
	}

	public void setRemoteDocumentValidationService(ShadowRemoteDocumentValidationService remoteDocumentValidationService) {
		this.remoteDocumentValidationService = remoteDocumentValidationService;
	}

	public SignatureFullValiationDTO validateDocument(RemoteDocument signedDocument, List<RemoteDocument> originalDocuments, RemoteDocument policy, TrustSources trust) {
		return validateDocument(signedDocument, originalDocuments, policy, trust, null);
	}

	public SignatureFullValiationDTO validateDocument(RemoteDocument signedDocument, List<RemoteDocument> originalDocuments, RemoteDocument policy, TrustSources trust, RemoteSignatureParameters parameters) {

		SignatureFullValiationDTO report = null;
		try {
			if (trust != null) {
				ThreadedCertificateVerifier.setExtraCertificateSource(trustSourcesToCertificateSource(trust));
				// Use custom trust policy
				if (policy == null) policy = getPolicyFile("Custom_trust_constraint.xml");
			}

			// Let DSS validate with provided, trust or default (null => Belgian) validation policy
			report = remoteDocumentValidationService.validateDocument(new DataToValidateDTO(signedDocument, originalDocuments, policy));
			if (policy == null && !documentHasBelgianSignature(report)) {
				// But in case of "pure non-belgian" document, use the default DSS policy
				report = remoteDocumentValidationService.validateDocument(new DataToValidateDTO(signedDocument, originalDocuments, getPolicyFile("DSS_constraint.xml")));
			}

			// When timestamp servers are down, DSS produced a signature that did not reflect the
			// requested "parameters.getSignatureLevel()". For example even though an LTA was requested the result is not LTA.
			// The code below is there to double-check this, it also makes sure SHA1 & MD5 are never used
			XmlDiagnosticData diagsData = report.getDiagnosticData();
			List<XmlSignature> signatures = diagsData.getSignatures();
			int sigCount = signatures.size();
			XmlSignature maxSig = null;
			for (int i = 0; i < sigCount; i++) {
				XmlSignature sig = signatures.get(i);
				// Check if the signature algo is MD5 or SHA1 and make it an error
				XmlBasicSignature basicSig = sig.getBasicSignature();
				DigestAlgorithm digestAlgo = basicSig.getDigestAlgoUsedToSignThisToken();
				if (digestAlgo != null) {
					String dAlgo = digestAlgo.toString();
					if ("SHA1".equals(dAlgo) || "MD5".equals(dAlgo)) {
						modifyReports(report, sig.getId(), SubIndication.CRYPTO_CONSTRAINTS_FAILURE,
								digestAlgo + " signatures not allowed");
					}
				}

				// Identify the latest signature (for next step)
				// Though this could not be the signature we "just made".
				// It would be better to identify the signature based on the signed digest but this one is still better than the previous one using the 10 seconds delay
				if (maxSig == null || sig.getClaimedSigningTime().after(maxSig.getClaimedSigningTime())) {
					maxSig = sig;
				}

				if (parameters != null && maxSig != null) {
					// Check if the signature level (of the sig we just made) corresponds with the requested level
					SignatureLevel expSigLevel = parameters.getSignatureLevel();
					SignatureLevel sigLevel = maxSig.getSignatureFormat();
					if (!sigLevel.equals(expSigLevel)) {
						modifyReports(report, maxSig.getId(), SubIndication.FORMAT_FAILURE, "expected level " + expSigLevel + " but was: " + sigLevel);
					}
				}
			}

		} catch (CertificateException | IOException | NoSuchAlgorithmException | KeyStoreException e) {
			// Exceptions linked to getCertificateSource keystore manipulation
			logAndThrowEx(BAD_REQUEST, INVALID_PARAM, e);
		} finally {
			ThreadedCertificateVerifier.clearExtraCertificateSource(); // Cleanup
		}
		return report;
	}

	private RemoteDocument getPolicyFile(String fileName) throws IOException {
		logger.warning("Loading policy for signature validation : " + fileName);
		InputStream genericIs = BosaRemoteDocumentValidationService.class.getResourceAsStream("/policy/" + fileName);
		if (genericIs == null) throw new IOException("Policy file not found");
		RemoteDocument policyDocument = new RemoteDocument(Utils.toByteArray(genericIs), fileName);
		genericIs.close();
		return policyDocument;
	}

	// The below password is only needed because, pre-Java 20 JVM, a "null" password keystore
	// ignores the certificates added to it. With Java 20 they are accepted.
	// This hardcoded password will of course trigger security review (sast or human)... although it should not since
	// the keystore is only held in memory (although not in "unswappable" memory... but that is another topic)
	private static final String SILLY_PASSWORD = "123456";
	private CertificateSource trustSourcesToCertificateSource(TrustSources trust) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {

		CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
		if (trust.getKeystore() != null) {
			String password = trust.getPassword();
			InputStream keyStoreStream = new ByteArrayInputStream(trust.getKeystore());
			KeyStoreCertificateSource keystoreCrtSrc = new KeyStoreCertificateSource(keyStoreStream, "PKCS12", password);
			trustedCertificateSource.importAsTrusted(keystoreCrtSrc);
		}

		if (trust.getCerts() != null) {
			// Ideally we should be able to add "cert" like this:
			//
			//		KeyStoreCertificateSource keystore = new KeyStoreCertificateSource("PKCS12", null);
			//		CertificateToken certificateToken = new CertificateToken(cert);
			//		keystore.addCertificate(certificateToken);
			//
			// but because "KeyStoreCertificateSource.importAsTrusted" depends on cert  aliases and CertificateToken doesn't set aliases
			// we're forced to use the inefficient code below : creating a keystore, add the cert (with alias ;-) ) , marshal the keystore and
			// unmarshal it as a KeyStoreCertificateSource
			KeyStore keyStore = KeyStore.getInstance("PKCS12");
			keyStore.load(null, null);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			int count = 0;
			for(byte[] certBytes : trust.getCerts()) {
				X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
				keyStore.setCertificateEntry("alias_" + Integer.toString(count++), cert);
			}
			ByteArrayOutputStream baos = new ByteArrayOutputStream(1000);

			keyStore.store(baos, SILLY_PASSWORD.toCharArray());
			InputStream keyStoreStream = new ByteArrayInputStream(baos.toByteArray());
			KeyStoreCertificateSource keystoreCrtSrc = new KeyStoreCertificateSource(keyStoreStream, "PKCS12", SILLY_PASSWORD);
			trustedCertificateSource.importAsTrusted(keystoreCrtSrc);
		}

		return trustedCertificateSource;
	}

	private boolean documentHasBelgianSignature(SignatureFullValiationDTO report) {
		for(XmlToken sigOrTS : report.getSimpleReport().getSignatureOrTimestamp()) {
			if (sigOrTS instanceof eu.europa.esig.dss.simplereport.jaxb.XmlSignature) {
				XmlCertificateChain certChain = sigOrTS.getCertificateChain();
				if (certChain == null) continue;
				List<XmlCertificate> certChain2 = certChain.getCertificate();
				XmlCertificate rootCert = certChain2.get(certChain2.size() - 1);
				if (isBelgianCertificate(report.getDiagnosticData().getUsedCertificates(), rootCert.getId())) return true;
			}
		}
	return false;
	}

	private boolean isBelgianCertificate(List<eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate> certs, String id) {
		for (eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate cert : certs) {
			if (id.equals(cert.getId())) {
				BigInteger sn = cert.getSerialNumber();
				if (BRCA6.equals(sn) || BRCA4.equals(sn) || BRCA3.equals(sn) || BRCA2.equals(sn) ||
						BRCA.equals(sn) || (testRootCertSN != null && testRootCertSN.equals(sn))) {
					return true;
				}
			}
		}
		return false;
	}

	private void modifyReports(SignatureFullValiationDTO report, String sigId, SubIndication subIndication, String errMesg) {
		// Modify the simple report
		XmlSimpleReport simpleReport = report.getSimpleReport();
		for (XmlToken token : simpleReport.getSignatureOrTimestamp()) {
			if (token.getId().equals(sigId)) {
				if (!Indication.TOTAL_FAILED.equals(token.getIndication())) {
					token.setIndication(Indication.TOTAL_FAILED);
					token.setSubIndication(subIndication);
					// DSS 5.8 had an "errors" field.
					// DSS 5.9 has AdESValidationDetails and QualificationDetails
					//			each have 3 lists of key/value pairs "error", "warning" and "info"
					// We're using the "error" list to add the error.
					XmlDetails adesValidationDetails = token.getAdESValidationDetails();
					if (adesValidationDetails == null) token.setAdESValidationDetails(adesValidationDetails = new XmlDetails());
					XmlMessage error = new XmlMessage();
					error.setKey("err");
					error.setValue(errMesg);
					adesValidationDetails.getError().add(error);
					int validSigsCount = simpleReport.getValidSignaturesCount();
					if (validSigsCount > 0)
						simpleReport.setValidSignaturesCount(validSigsCount - 1);
				}
				break;
			}
		}
		// Modify the detailed report
		for (Serializable sigTsOrCert : report.getDetailedReport().getSignatureOrTimestampOrCertificate()) {
			eu.europa.esig.dss.detailedreport.jaxb.XmlSignature signat = (eu.europa.esig.dss.detailedreport.jaxb.XmlSignature)sigTsOrCert;
			if (signat.getId().equals(sigId)) {
				XmlValidationProcessBasicSignature validation = signat.getValidationProcessBasicSignature();
				XmlConclusion conclusion = validation.getConclusion();
				conclusion.setIndication(Indication.TOTAL_FAILED);
				conclusion.setSubIndication(subIndication);

				eu.europa.esig.dss.detailedreport.jaxb.XmlMessage err = new eu.europa.esig.dss.detailedreport.jaxb.XmlMessage();
				err.setKey("err");
				err.setValue(errMesg);
				conclusion.getErrors().add(err);
				break;
			}
		}
	}
}

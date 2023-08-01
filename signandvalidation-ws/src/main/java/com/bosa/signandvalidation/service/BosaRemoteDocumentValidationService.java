package com.bosa.signandvalidation.service;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.List;
import java.io.Serializable;
import java.util.logging.Logger;

import com.bosa.signandvalidation.model.SignatureFullValiationDTO;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDistinguishedName;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.simplereport.jaxb.*;
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


	private static final String GENERIC_POLICY = "DSS_constraint.xml";
	private static final Logger logger = Logger.getLogger(BosaRemoteDocumentValidationService.class.getName());
	private ShadowRemoteDocumentValidationService remoteDocumentValidationService;

	public BosaRemoteDocumentValidationService() {
	}

	public void setRemoteDocumentValidationService(ShadowRemoteDocumentValidationService remoteDocumentValidationService) {
		this.remoteDocumentValidationService = remoteDocumentValidationService;
	}

	public SignatureFullValiationDTO validateDocument(RemoteDocument signedDocument, List<RemoteDocument> originalDocuments, RemoteDocument policy) {
		return validateDocument(signedDocument, originalDocuments, policy, null);
	}

	public SignatureFullValiationDTO validateDocument(RemoteDocument signedDocument, List<RemoteDocument> originalDocuments, RemoteDocument policy, RemoteSignatureParameters parameters) {

		// Let DSS validate with provided or default (null => Belgian) validation policy
		SignatureFullValiationDTO report = remoteDocumentValidationService.validateDocument(new DataToValidateDTO(signedDocument, originalDocuments, policy));
		if (policy == null && !documentHasBelgianSignature(report)) {
			logger.warning("Validation with default policy of a document that does not contain Belgian signatures. Using generic policy to validate");
			try {
				InputStream genericIs = BosaRemoteDocumentValidationService.class.getResourceAsStream("/policy/" + GENERIC_POLICY);
				RemoteDocument genericPolicy = new RemoteDocument(Utils.toByteArray(genericIs), GENERIC_POLICY);
				genericIs.close();
				report = remoteDocumentValidationService.validateDocument(new DataToValidateDTO(signedDocument, originalDocuments, genericPolicy));
			} catch (IOException e) {
				throw new RuntimeException(GENERIC_POLICY + " not found");
			}
		}

		// When some back end servers (don't know which ones...) are down seems DSS can produce a signature that does not reflect the
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
		}

		if (parameters != null && maxSig != null) {
			// Check if the signature level (of the sig we just made) corresponds with the requested level
			SignatureLevel expSigLevel = parameters.getSignatureLevel();
			SignatureLevel sigLevel = maxSig.getSignatureFormat();
			if (!sigLevel.equals(expSigLevel)) {
				modifyReports(report, maxSig.getId(), SubIndication.FORMAT_FAILURE, "expected level " + expSigLevel + " but was: " + sigLevel);
			}
		}

		return report;
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

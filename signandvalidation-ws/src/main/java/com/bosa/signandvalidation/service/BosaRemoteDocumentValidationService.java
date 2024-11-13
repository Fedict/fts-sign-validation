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

import com.bosa.signandvalidation.config.ThreadInterception;
import com.bosa.signandvalidation.model.SignatureFullValiationDTO;
import com.bosa.signandvalidation.model.TrustSources;
import eu.europa.esig.dss.detailedreport.jaxb.*;
import eu.europa.esig.dss.diagnostic.jaxb.*;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.simplereport.jaxb.*;
import eu.europa.esig.dss.simplereport.jaxb.XmlCertificateChain;
import eu.europa.esig.dss.simplereport.jaxb.XmlMessage;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.validation.dto.DataToValidateDTO;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.Marshaller;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import static com.bosa.signandvalidation.config.ErrorStrings.INVALID_PARAM;
import static com.bosa.signandvalidation.exceptions.Utils.getPolicyFile;
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
	static BigInteger testRootCertSN;

	private static final Logger logger = Logger.getLogger(BosaRemoteDocumentValidationService.class.getName());
	@Setter
    private ShadowRemoteDocumentValidationService remoteDocumentValidationService;

	public BosaRemoteDocumentValidationService() {
	}

    public SignatureFullValiationDTO validateDocument(RemoteDocument signedDocument, List<RemoteDocument> originalDocuments, RemoteDocument policy, TrustSources trust) {
		return validateDocument(signedDocument, originalDocuments, policy, trust, null);
	}

	public SignatureFullValiationDTO validateDocument(RemoteDocument signedDocument, List<RemoteDocument> originalDocuments, RemoteDocument policy, TrustSources trust, SignatureLevel expectedSigLevel) {

		WSReportsDTO report = null;
		try {
			if (trust != null) {
				ThreadInterception.setExtraCertificateSource(trustSourcesToCertificateSource(trust));
				// Use custom trust policy
				if (policy == null) policy = getPolicyFile("Custom_trust_constraint.xml");
			}

			// Let DSS validate with provided, trust or default (null => Belgian) validation policy
			report = remoteDocumentValidationService.validateDocument(new DataToValidateDTO(signedDocument, originalDocuments, policy), expectedSigLevel != null);
			if (policy == null) {
				int nbNonBelgianSignatures = countNonBelgianSignatures(report);
				boolean allNonBelgianSignatures = report.getDetailedReport().getSignatureOrTimestampOrEvidenceRecord().size() == nbNonBelgianSignatures;
				if (nbNonBelgianSignatures != 0 || allNonBelgianSignatures) {
					// But in case of mixed "belgian/non-belgian" or pure "non-belgian" document, use the default DSS policy
					WSReportsDTO reportDSS = remoteDocumentValidationService.validateDocument(new DataToValidateDTO(signedDocument, originalDocuments, getPolicyFile("DSS_constraint.xml")), true);
					report = allNonBelgianSignatures ? reportDSS : mergeValidationReports(report, reportDSS);
				}
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
			}

			if (expectedSigLevel != null && maxSig != null) {
				// Check if the signature level (of the sig we just made) corresponds with the requested level
				SignatureLevel sigLevel = maxSig.getSignatureFormat();
				if (!sigLevel.equals(expectedSigLevel)) {
					modifyReports(report, maxSig.getId(), SubIndication.FORMAT_FAILURE, "expected level " + expectedSigLevel + " but was: " + sigLevel);
				}
			}
		} catch (CertificateException | IOException | NoSuchAlgorithmException | KeyStoreException e) {
			// Exceptions linked to getCertificateSource keystore manipulation
			logAndThrowEx(BAD_REQUEST, INVALID_PARAM, e);
		}
		return new SignatureFullValiationDTO(report);
	}

	// Merge two DSS reports taking all Belgian-certificate results from the beReport and others from the dssReport and recalculating the conclusions
	private static WSReportsDTO mergeValidationReports(WSReportsDTO beReport, WSReportsDTO dssReport) {
		//dumpReport(beReport, "beReport.xml");
		//dumpReport(dssReport, "dssReport.xml");
		WSReportsDTO result = new WSReportsDTO();
		result.setDiagnosticData(beReport.getDiagnosticData());
		result.setSimpleReport(buildSimpleReport(beReport, dssReport));
		result.setDetailedReport(buildDetailedReport(beReport, dssReport));
		result.setValidationReportDataHandler(beReport.getValidationReportDataHandler());
		//dumpReport(result, "result.xml");
		return result;
	}

	private static XmlDetailedReport buildDetailedReport(WSReportsDTO beReport, WSReportsDTO dssReport) {
		XmlDetailedReport dReport = new XmlDetailedReport();
		XmlDetailedReport bedReport = beReport.getDetailedReport();
		dReport.setValidationTime(bedReport.getValidationTime());
		// Add all "BE" signatures from beReport to target Detailed Report
		addDetailedSignatures(beReport, beReport, true, dReport);
		// Add all non "BE" signatures from dssReport to target Detailed Report
		addDetailedSignatures(beReport, dssReport, false, dReport);
		return dReport;
	}

	private static void addDetailedSignatures(WSReportsDTO beReport, WSReportsDTO xReport, boolean hasBelgianRootCert, XmlDetailedReport dReport) {
		XmlDetailedReport xdReport = xReport.getDetailedReport();
		List<XmlBasicBuildingBlocks> dBasicBuildingBlocks = dReport.getBasicBuildingBlocks();
		List<Serializable> targetSignatures = dReport.getSignatureOrTimestampOrEvidenceRecord();
		for(Serializable token : xdReport.getSignatureOrTimestampOrEvidenceRecord()) {
			if (token instanceof eu.europa.esig.dss.detailedreport.jaxb.XmlSignature) {
				eu.europa.esig.dss.detailedreport.jaxb.XmlSignature signature = (eu.europa.esig.dss.detailedreport.jaxb.XmlSignature)token;
				if (isSignatureBEorNot(beReport.getSimpleReport(), signature.getId(), hasBelgianRootCert)) {
					targetSignatures.add(signature);
					addRevocationBasicBuildingBlocks(xReport, signature.getId(), dBasicBuildingBlocks);
					addBasicBuildingBlocks(xdReport, signature, dBasicBuildingBlocks);
				}
			}
		}

		addTLAnalysisBuildingBlocks(xdReport, hasBelgianRootCert, dReport.getTLAnalysis());
	}

	private static void addTLAnalysisBuildingBlocks(XmlDetailedReport xdReport, boolean hasBelgianRootCert, List<XmlTLAnalysis> tlAnalyses) {
		for (XmlTLAnalysis xtlAnalysis : xdReport.getTLAnalysis()) {
			String country = xtlAnalysis.getCountryCode();
			if (country.compareToIgnoreCase("EU") == 0 ||
					(hasBelgianRootCert && country.compareToIgnoreCase("BE") == 0) ||
					(!hasBelgianRootCert && country.compareToIgnoreCase("BE") != 0)) addUniqueTLAnalysis(xtlAnalysis, tlAnalyses);
		}
	}

	private static void addUniqueTLAnalysis(XmlTLAnalysis xtlAnalysis, List<XmlTLAnalysis> tlAnalyses) {
		for (XmlTLAnalysis tlAnalysis : tlAnalyses) {
			if (tlAnalysis.getId().compareToIgnoreCase(xtlAnalysis.getId()) == 0) return;
		}
		tlAnalyses.add(xtlAnalysis);
	}

	private static void addRevocationBasicBuildingBlocks(WSReportsDTO xReport, String signatureID, List<XmlBasicBuildingBlocks> dbbbs) {
		XmlDiagnosticData diagData = xReport.getDiagnosticData();
		for(XmlSignature signature : diagData.getSignatures()) {
				if (signature.getId().compareToIgnoreCase(signatureID) == 0) {
					XmlFoundRevocations foundRevocations = signature.getFoundRevocations();
					for (XmlRelatedRevocation foundRevocation : foundRevocations.getRelatedRevocations()) {
						addUniqueRevocationBasicBuildingBlocks(foundRevocation.getRevocation().getId(), xReport, dbbbs);
					}
					for (XmlOrphanRevocation foundRevocation : foundRevocations.getOrphanRevocations()) {
						addUniqueRevocationBasicBuildingBlocks(foundRevocation.getToken().getId(), xReport, dbbbs);
					}
				}
			}
		for(XmlCertificate usedCert : diagData.getUsedCertificates()) {
			for(XmlCertificateRevocation revocation : usedCert.getRevocations()) {
				addUniqueRevocationBasicBuildingBlocks(revocation.getRevocation().getId(), xReport, dbbbs);
			}
		}
	}

	private static void addUniqueRevocationBasicBuildingBlocks(String id, WSReportsDTO xReport, List<XmlBasicBuildingBlocks> dbbbs) {
		for(XmlBasicBuildingBlocks bbb : xReport.getDetailedReport().getBasicBuildingBlocks()) {
			if (bbb.getId().compareToIgnoreCase(id) == 0) {
				System.out.println("ID : " + id);
				addUniqueBasicBuildingBlock(dbbbs, bbb);
				return;
			}
		}
	}

	private static void addBasicBuildingBlocks(XmlDetailedReport xdReport, eu.europa.esig.dss.detailedreport.jaxb.XmlSignature signature, List<XmlBasicBuildingBlocks> dbbbs) {
		for (eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp ts : signature.getTimestamps()) {
			for(XmlBasicBuildingBlocks bbb : xdReport.getBasicBuildingBlocks()) {
				if (ts.getId().compareToIgnoreCase(bbb.getId()) == 0) {
					addUniqueBasicBuildingBlock(dbbbs, bbb);
				}
			}
		}
		for(XmlBasicBuildingBlocks bbb : xdReport.getBasicBuildingBlocks()) {
			if (signature.getId().compareToIgnoreCase(bbb.getId()) == 0) dbbbs.add(bbb);
		}
	}

	// If not already present in the target BB list, add  BB
	private static void addUniqueBasicBuildingBlock(List<XmlBasicBuildingBlocks> dbbbs, XmlBasicBuildingBlocks bbToAdd) {
		for (XmlBasicBuildingBlocks bbb : dbbbs) {
			if (bbToAdd.getId().compareToIgnoreCase(bbb.getId()) == 0) {
				System.out.println("SKIP ID : " + bbToAdd.getId());
				return;
			}
		}
		dbbbs.add(bbToAdd);
	}

	private static XmlSimpleReport buildSimpleReport(WSReportsDTO beReport, WSReportsDTO dssReport) {
		XmlSimpleReport sReport = new XmlSimpleReport();
		XmlSimpleReport besReport = beReport.getSimpleReport();
		sReport.setValidationTime(besReport.getValidationTime());
		XmlValidationPolicy validationPolicy = new XmlValidationPolicy();
		validationPolicy.setPolicyName("Mixed policy");
		validationPolicy.setPolicyDescription("File was validated with the Belgian Policy and with the international policy. The resulting report is a mix of both");
		sReport.setValidationPolicy(validationPolicy);
		sReport.setSignaturesCount(besReport.getSignaturesCount());
		sReport.setDocumentName(besReport.getDocumentName());
		int validSignatures = addSimpleSignatures(besReport, true, sReport.getSignatureOrTimestampOrEvidenceRecord());
		validSignatures += addSimpleSignatures(dssReport.getSimpleReport(), false, sReport.getSignatureOrTimestampOrEvidenceRecord());
		sReport.setValidSignaturesCount(validSignatures);
		return sReport;
	}

	private static int addSimpleSignatures(XmlSimpleReport sReport, boolean hasBelgianRootCert, List<XmlToken> signatures) {
		int validSignatures = 0;
		for(XmlToken token : sReport.getSignatureOrTimestampOrEvidenceRecord()) {
			if (token instanceof eu.europa.esig.dss.simplereport.jaxb.XmlSignature) {
				eu.europa.esig.dss.simplereport.jaxb.XmlSignature signature = (eu.europa.esig.dss.simplereport.jaxb.XmlSignature)token;
				if (isSignatureBEorNot(signature, hasBelgianRootCert)) {
					signatures.add(token);
					if (Indication.TOTAL_PASSED.equals(signature.getIndication())) validSignatures++;
				}
			}
		}
		return validSignatures;
	}

	private static boolean isSignatureBEorNot(XmlSimpleReport besReport, String sigID, boolean hasBelgianRootCert) {
		for(XmlToken token : besReport.getSignatureOrTimestampOrEvidenceRecord()) {
			if (token instanceof eu.europa.esig.dss.simplereport.jaxb.XmlSignature) {
				eu.europa.esig.dss.simplereport.jaxb.XmlSignature signature = (eu.europa.esig.dss.simplereport.jaxb.XmlSignature)token;
				if (signature.getId().compareToIgnoreCase(sigID) == 0) return isSignatureBEorNot(signature, hasBelgianRootCert);
			}
		}
		return false;
	}

	private static boolean isSignatureBEorNot(eu.europa.esig.dss.simplereport.jaxb.XmlSignature signature, boolean hasBelgianRootCert) {
		for(eu.europa.esig.dss.simplereport.jaxb.XmlCertificate cert : signature.getCertificateChain().getCertificate()) {
			if (cert.isTrusted()) {
				XmlTrustAnchors trustAnchors = cert.getTrustAnchors();
				if (trustAnchors != null) {
					for (XmlTrustAnchor trustAnchor : trustAnchors.getTrustAnchor()) {
						String country = trustAnchor.getCountryCode();
						if (country != null) {
							int comp = country.compareToIgnoreCase("BE");
							if ((hasBelgianRootCert && comp == 0) || (!hasBelgianRootCert && comp != 0)) return true;
						}
					}
				}
			}
		}
		return false;
	}

	private static void dumpReport(WSReportsDTO report, String fileName) {
		try  {
			JAXBContext jaxbContext = JAXBContext.newInstance(BosaRemoteDocumentValidationService.XmlReportRoot.class);
			Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
			jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
			BosaRemoteDocumentValidationService.XmlReportRoot root = new BosaRemoteDocumentValidationService.XmlReportRoot();
			root.setReport(report);
			StringWriter sw = new StringWriter();
			jaxbMarshaller.marshal(root, sw);

			try (FileOutputStream fos = new FileOutputStream(fileName)) { fos.write(sw.toString().getBytes()); }
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	@XmlRootElement
	@XmlAccessorType(XmlAccessType.FIELD)
	private static class XmlReportRoot {

		private WSReportsDTO report;

		public void setReport(WSReportsDTO report) {
			this.report = report;
		}
	}


	// The below password is only needed because, pre-Java 20 JVM, a "null" password keystore
	// ignores the certificates added to it. With Java 20 they are accepted.
	// This hardcoded password will of course trigger security review (sast or human)... although it should not since
	// the keystore is only held in memory (although not in "unswappable" memory... but that is another topic)

	private static final char [] SILLY_PASSWORD = "123456".toCharArray();

	private CertificateSource trustSourcesToCertificateSource(TrustSources trust) throws CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {

		CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
		if (trust.getKeystore() != null) {
			String password = trust.getPassword();
			InputStream keyStoreStream = new ByteArrayInputStream(trust.getKeystore());
			KeyStoreCertificateSource keystoreCrtSrc = new KeyStoreCertificateSource(keyStoreStream, "PKCS12", password == null ? null : password.toCharArray());
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

			keyStore.store(baos, SILLY_PASSWORD);
			InputStream keyStoreStream = new ByteArrayInputStream(baos.toByteArray());
			KeyStoreCertificateSource keystoreCrtSrc = new KeyStoreCertificateSource(keyStoreStream, "PKCS12", SILLY_PASSWORD);
			trustedCertificateSource.importAsTrusted(keystoreCrtSrc);
		}

		return trustedCertificateSource;
	}

	private static int countNonBelgianSignatures(WSReportsDTO report) {
		int nbSignatures = 0;
		for(XmlToken sigOrTS : report.getSimpleReport().getSignatureOrTimestampOrEvidenceRecord()) {
			if (sigOrTS instanceof eu.europa.esig.dss.simplereport.jaxb.XmlSignature) {
				XmlCertificateChain certChain = sigOrTS.getCertificateChain();
				if (certChain == null) continue;
				List<eu.europa.esig.dss.simplereport.jaxb.XmlCertificate> certChain2 = certChain.getCertificate();
				eu.europa.esig.dss.simplereport.jaxb.XmlCertificate rootCert = certChain2.get(certChain2.size() - 1);
				if (!isBelgianTestOrRootCertificate(report.getDiagnosticData().getUsedCertificates(), rootCert.getId())) nbSignatures++;
			}
		}
	return nbSignatures;
	}

	private static boolean isBelgianTestOrRootCertificate(List<eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate> certs, String id) {
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

	private void modifyReports(WSReportsDTO report, String sigId, SubIndication subIndication, String errMesg) {
		// Modify the simple report
		XmlSimpleReport simpleReport = report.getSimpleReport();
		for (XmlToken token : simpleReport.getSignatureOrTimestampOrEvidenceRecord()) {
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
		for (Serializable sigTsOrCert : report.getDetailedReport().getSignatureOrTimestampOrEvidenceRecord()) {
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

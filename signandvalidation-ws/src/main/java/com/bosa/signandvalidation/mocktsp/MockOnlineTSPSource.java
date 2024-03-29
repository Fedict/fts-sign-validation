package com.bosa.signandvalidation.mocktsp;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.token.KSPrivateKeyEntry;
import eu.europa.esig.dss.token.KeyStoreSignatureTokenConnection;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

public class MockOnlineTSPSource extends OnlineTSPSource {

    private static final long serialVersionUID = 8863748492343274842L;

    private final Logger LOG = LoggerFactory.getLogger(MockOnlineTSPSource.class);

    private final static SecureRandom random = new SecureRandom();

    private KeyStoreSignatureTokenConnection token;

    private String alias;

    public void setToken(KeyStoreSignatureTokenConnection token) {
        this.token = token;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    @Override
    public TimestampBinary getTimeStampResponse(DigestAlgorithm digestAlgorithm, byte[] digest) {
        if (token == null) {
            throw new DSSException("KeyStore token is not defined!");
        }
        try {
            TimeStampRequestGenerator requestGenerator = new TimeStampRequestGenerator();
            requestGenerator.setCertReq(true);
            TimeStampRequest request = requestGenerator.generate(new ASN1ObjectIdentifier(digestAlgorithm.getOid()), digest);

            KSPrivateKeyEntry ksPK = (KSPrivateKeyEntry) token.getKey(alias);
            if (ksPK == null) {
                throw new DSSException("Unable to initialize the MockTSPSource");
            }

            LOG.info("Timestamping with {}", ksPK.getCertificate());

            X509CertificateHolder certificate = new X509CertificateHolder(ksPK.getCertificate().getEncoded());
            List<X509Certificate> chain = new ArrayList<X509Certificate>();
            CertificateToken[] certificateChain = ksPK.getCertificateChain();
            for (CertificateToken token : certificateChain) {
                chain.add(token.getCertificate());
            }

            Set<ASN1ObjectIdentifier> accepted = new HashSet<ASN1ObjectIdentifier>();
            accepted.add(TSPAlgorithms.SHA1);
            accepted.add(TSPAlgorithms.SHA256);
            accepted.add(TSPAlgorithms.SHA512);

            AlgorithmIdentifier digestAlgorithmIdentifier = new AlgorithmIdentifier(new ASN1ObjectIdentifier(digestAlgorithm.getOid()));
            AlgorithmIdentifier encryptionAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption);

            DefaultCMSSignatureAlgorithmNameGenerator sigAlgoGenerator = new DefaultCMSSignatureAlgorithmNameGenerator();
            String sigAlgoName = sigAlgoGenerator.getSignatureName(digestAlgorithmIdentifier, encryptionAlg);

            ContentSigner signer = new JcaContentSignerBuilder(sigAlgoName).build(ksPK.getPrivateKey());

            SignerInfoGenerator infoGenerator = new SignerInfoGeneratorBuilder(new BcDigestCalculatorProvider()).build(signer, certificate);
            DigestCalculator digestCalculator = new JcaDigestCalculatorProviderBuilder().build().get(digestAlgorithmIdentifier);

            TimeStampTokenGenerator tokenGenerator = new TimeStampTokenGenerator(infoGenerator, digestCalculator, new ASN1ObjectIdentifier("1.2.3.4"));
            tokenGenerator.addCertificates(new JcaCertStore(chain));

            TimeStampResponseGenerator responseGenerator = new TimeStampResponseGenerator(tokenGenerator, accepted);
            TimeStampResponse response = responseGenerator.generate(request, new BigInteger(128, random), new Date());

            return new TimestampBinary(DSSASN1Utils.getDEREncoded(response.getTimeStampToken()));
        } catch (IOException | TSPException | OperatorException | CertificateException e) {
            throw new DSSException("Unable to generate a timestamp from the Mock", e);
        }
    }

}

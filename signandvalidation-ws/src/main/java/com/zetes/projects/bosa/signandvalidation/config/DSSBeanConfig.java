package com.zetes.projects.bosa.signandvalidation.config;

import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.service.crl.JdbcCacheCRLSource;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.service.http.proxy.ProxyConfig;
import eu.europa.esig.dss.service.ocsp.JdbcCacheOCSPSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.tsl.function.OfficialJournalSchemeInformationURI;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.ws.cert.validation.common.RemoteCertificateValidationService;
import eu.europa.esig.dss.ws.signature.common.RemoteDocumentSignatureServiceImpl;
import eu.europa.esig.dss.ws.signature.common.RemoteMultipleDocumentsSignatureServiceImpl;
import eu.europa.esig.dss.ws.validation.common.RemoteDocumentValidationService;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.sql.DataSource;
import java.io.File;
import java.io.IOException;
import java.sql.SQLException;

@Configuration
public class DSSBeanConfig {

    private static final Logger LOG = LoggerFactory.getLogger(DSSBeanConfig.class);

    @Value("${current.lotl.url}")
    private String lotlUrl;

    @Value("${lotl.country.code}")
    private String lotlCountryCode;

    @Value("${current.oj.url}")
    private String currentOjUrl;

    @Value("${oj.content.keystore.type}")
    private String ksType;

    @Value("${oj.content.keystore.filename}")
    private String ksFilename;

    @Value("${oj.content.keystore.password}")
    private String ksPassword;

    @Value("${test.keystore.enabled}")
    private Boolean testKsenabled;

    @Value("${test.keystore.type}")
    private String testKsType;

    @Value("${test.keystore.filename}")
    private String testKsFilename;

    @Value("${test.keystore.password}")
    private String testKsPassword;

    @Autowired
    private DataSource dataSource;

    @Autowired
    private TSPSource tspSource;

    // can be null
    @Autowired(required = false)
    private ProxyConfig proxyConfig;

    @PostConstruct
    public void cachedCRLSourceInitialization() throws SQLException {
        JdbcCacheCRLSource jdbcCacheCRLSource = cachedCRLSource();
        jdbcCacheCRLSource.initTable();
    }

    @PostConstruct
    public void cachedOCSPSourceInitialization() throws SQLException {
        JdbcCacheOCSPSource jdbcCacheOCSPSource = cachedOCSPSource();
        jdbcCacheOCSPSource.initTable();
    }

    @PreDestroy
    public void cachedCRLSourceClean() throws SQLException {
        JdbcCacheCRLSource jdbcCacheCRLSource = cachedCRLSource();
        jdbcCacheCRLSource.destroyTable();
    }

    @PreDestroy
    public void cachedOCSPSourceClean() throws SQLException {
        JdbcCacheOCSPSource jdbcCacheOCSPSource = cachedOCSPSource();
        jdbcCacheOCSPSource.destroyTable();
    }

    @Bean
    public CommonsDataLoader dataLoader() {
        CommonsDataLoader dataLoader = new CommonsDataLoader();
        dataLoader.setProxyConfig(proxyConfig);
        return dataLoader;
    }

    @Bean
    public OCSPDataLoader ocspDataLoader() {
        OCSPDataLoader ocspDataLoader = new OCSPDataLoader();
        ocspDataLoader.setProxyConfig(proxyConfig);
        return ocspDataLoader;
    }

    @Bean
    public FileCacheDataLoader fileCacheDataLoader() {
        FileCacheDataLoader fileCacheDataLoader = new FileCacheDataLoader();
        fileCacheDataLoader.setDataLoader(dataLoader());
        // Per default uses "java.io.tmpdir" property
        // fileCacheDataLoader.setFileCacheDirectory(new File("/tmp"));
        return fileCacheDataLoader;
    }

    @Bean
    public OnlineCRLSource onlineCRLSource() {
        OnlineCRLSource onlineCRLSource = new OnlineCRLSource();
        onlineCRLSource.setDataLoader(dataLoader());
        return onlineCRLSource;
    }

    @Bean
    public JdbcCacheCRLSource cachedCRLSource() {
        JdbcCacheCRLSource jdbcCacheCRLSource = new JdbcCacheCRLSource();
        jdbcCacheCRLSource.setDataSource(dataSource);
        jdbcCacheCRLSource.setProxySource(onlineCRLSource());
        jdbcCacheCRLSource.setDefaultNextUpdateDelay((long) (60 * 3)); // 3 minutes
        return jdbcCacheCRLSource;
    }

    @Bean
    public OnlineOCSPSource onlineOcspSource() {
        OnlineOCSPSource onlineOCSPSource = new OnlineOCSPSource();
        onlineOCSPSource.setDataLoader(ocspDataLoader());
        return onlineOCSPSource;
    }

    @Bean
    public JdbcCacheOCSPSource cachedOCSPSource() {
        JdbcCacheOCSPSource jdbcCacheOCSPSource = new JdbcCacheOCSPSource();
        jdbcCacheOCSPSource.setDataSource(dataSource);
        jdbcCacheOCSPSource.setProxySource(onlineOcspSource());
        jdbcCacheOCSPSource.setDefaultNextUpdateDelay((long) (1000 * 60 * 3)); // 3 minutes
        return jdbcCacheOCSPSource;
    }

    @Bean(name = "european-trusted-list-certificate-source")
    public TrustedListsCertificateSource trustedListSource() {
        return new TrustedListsCertificateSource();
    }

    @Bean(name = "test-certificate-source")
    public CertificateSource testTrustStoreSource() throws IOException {
        if (testKsenabled) {
            KeyStoreCertificateSource keystore = new KeyStoreCertificateSource(
                    new ClassPathResource(testKsFilename).getFile(), testKsType, testKsPassword
            );

            CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
            trustedCertificateSource.importAsTrusted(keystore);

            return trustedCertificateSource;
        } else {
            return null;
        }
    }

    @Bean
    public CertificateVerifier certificateVerifier() throws Exception {
        CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
        certificateVerifier.setCrlSource(cachedCRLSource());
        certificateVerifier.setOcspSource(cachedOCSPSource());
        certificateVerifier.setDataLoader(dataLoader());
        certificateVerifier.setTrustedCertSource(trustedListSource());
        if (testKsenabled) {
            certificateVerifier.setTrustedCertSource(testTrustStoreSource());
        }

        // Default configs
        certificateVerifier.setExceptionOnMissingRevocationData(true);
        certificateVerifier.setCheckRevocationForUntrustedChains(false);

        return certificateVerifier;
    }

    @Bean
    public CAdESService cadesService() throws Exception {
        CAdESService service = new CAdESService(certificateVerifier());
        service.setTspSource(tspSource);
        return service;
    }

    @Bean
    public XAdESService xadesService() throws Exception {
        XAdESService service = new XAdESService(certificateVerifier());
        service.setTspSource(tspSource);
        return service;
    }

    @Bean
    public PAdESService padesService() throws Exception {
        PAdESService service = new PAdESService(certificateVerifier());
        service.setTspSource(tspSource);
        return service;
    }

    @Bean
    public ASiCWithCAdESService asicWithCadesService() throws Exception {
        ASiCWithCAdESService service = new ASiCWithCAdESService(certificateVerifier());
        service.setTspSource(tspSource);
        return service;
    }

    @Bean
    public ASiCWithXAdESService asicWithXadesService() throws Exception {
        ASiCWithXAdESService service = new ASiCWithXAdESService(certificateVerifier());
        service.setTspSource(tspSource);
        return service;
    }

    @Bean
    public RemoteDocumentSignatureServiceImpl remoteSignatureService() throws Exception {
        RemoteDocumentSignatureServiceImpl service = new RemoteDocumentSignatureServiceImpl();
        service.setAsicWithCAdESService(asicWithCadesService());
        service.setAsicWithXAdESService(asicWithXadesService());
        service.setCadesService(cadesService());
        service.setXadesService(xadesService());
        service.setPadesService(padesService());
        return service;
    }

    @Bean
    public RemoteMultipleDocumentsSignatureServiceImpl remoteMultipleDocumentsSignatureService() throws Exception {
        RemoteMultipleDocumentsSignatureServiceImpl service = new RemoteMultipleDocumentsSignatureServiceImpl();
        service.setAsicWithCAdESService(asicWithCadesService());
        service.setAsicWithXAdESService(asicWithXadesService());
        service.setXadesService(xadesService());
        return service;
    }

    @Bean
    public RemoteDocumentValidationService remoteValidationService() throws Exception {
        RemoteDocumentValidationService service = new RemoteDocumentValidationService();
        service.setVerifier(certificateVerifier());
        return service;
    }

    @Bean
    public RemoteCertificateValidationService RemoteCertificateValidationService() throws Exception {
        RemoteCertificateValidationService service = new RemoteCertificateValidationService();
        service.setVerifier(certificateVerifier());
        return service;
    }

    @Bean
    public KeyStoreCertificateSource ojContentKeyStore() {
        try {
            return new KeyStoreCertificateSource(new ClassPathResource(ksFilename).getFile(), ksType, ksPassword);
        } catch (IOException e) {
            throw new DSSException("Unable to load the file " + ksFilename, e);
        }
    }

    @Bean
    public TLValidationJob job() {
        TLValidationJob job = new TLValidationJob();
        job.setTrustedListCertificateSource(trustedListSource());
        job.setListOfTrustedListSources(europeanLOTL());
        job.setOfflineDataLoader(offlineLoader());
        job.setOnlineDataLoader(onlineLoader());
        return job;
    }

    @Bean
    public DSSFileLoader onlineLoader() {
        FileCacheDataLoader offlineFileLoader = new FileCacheDataLoader();
        offlineFileLoader.setCacheExpirationTime(0);
        offlineFileLoader.setDataLoader(dataLoader());
        offlineFileLoader.setFileCacheDirectory(tlCacheDirectory());
        return offlineFileLoader;
    }

    @Bean(name = "european-lotl-source")
    public LOTLSource europeanLOTL() {
        LOTLSource lotlSource = new LOTLSource();
        lotlSource.setUrl(lotlUrl);
        lotlSource.setCertificateSource(ojContentKeyStore());
        lotlSource.setSigningCertificatesAnnouncementPredicate(new OfficialJournalSchemeInformationURI(currentOjUrl));
        lotlSource.setPivotSupport(true);
        return lotlSource;
    }

    @Bean
    public DSSFileLoader offlineLoader() {
        FileCacheDataLoader offlineFileLoader = new FileCacheDataLoader();
        offlineFileLoader.setCacheExpirationTime(Long.MAX_VALUE);
        offlineFileLoader.setDataLoader(new IgnoreDataLoader());
        offlineFileLoader.setFileCacheDirectory(tlCacheDirectory());
        return offlineFileLoader;
    }

    @Bean
    public File tlCacheDirectory() {
        File rootFolder = new File(System.getProperty("java.io.tmpdir"));
        File tslCache = new File(rootFolder, "dss-tsl-loader");
        if (tslCache.mkdirs()) {
            LOG.info("TL Cache folder : {}", tslCache.getAbsolutePath());
        }
        return tslCache;
    }

}

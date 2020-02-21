package com.zetes.projects.bosa.signandvalidation.config;

import eu.europa.esig.dss.service.crl.JdbcCacheCRLSource;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.service.http.proxy.ProxyConfig;
import eu.europa.esig.dss.service.ocsp.JdbcCacheOCSPSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.tsl.service.TSLRepository;
import eu.europa.esig.dss.tsl.service.TSLValidationJob;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.ws.cert.validation.common.RemoteCertificateValidationService;
import eu.europa.esig.dss.ws.validation.common.RemoteDocumentValidationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.sql.DataSource;
import java.io.IOException;
import java.sql.SQLException;

@Configuration
public class DSSBeanConfig {

    @Value("${default.validation.policy}")
    private String defaultValidationPolicy;

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

    @Autowired
    private DataSource dataSource;

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

    @Bean
    public TrustedListsCertificateSource trustedListSource() {
        return new TrustedListsCertificateSource();
    }

    @Bean
    public CertificateVerifier certificateVerifier() throws Exception {
        CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
        certificateVerifier.setTrustedCertSource(trustedListSource());
        certificateVerifier.setCrlSource(cachedCRLSource());
        certificateVerifier.setOcspSource(cachedOCSPSource());
        certificateVerifier.setDataLoader(dataLoader());

        // Default configs
        certificateVerifier.setExceptionOnMissingRevocationData(true);
        certificateVerifier.setCheckRevocationForUntrustedChains(false);

        return certificateVerifier;
    }

    @Bean
    public ClassPathResource defaultPolicy() {
        return new ClassPathResource(defaultValidationPolicy);
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
    public TSLRepository tslRepository(TrustedListsCertificateSource trustedListSource) {
        TSLRepository tslRepository = new TSLRepository();
        tslRepository.setTrustedListsCertificateSource(trustedListSource);
        return tslRepository;
    }

    @Bean
    public KeyStoreCertificateSource ojContentKeyStore() throws IOException {
        return new KeyStoreCertificateSource(new ClassPathResource(ksFilename).getFile(), ksType, ksPassword);
    }

    @Bean
    public TSLValidationJob tslValidationJob(DataLoader dataLoader, TSLRepository tslRepository, KeyStoreCertificateSource ojContentKeyStore) {
        TSLValidationJob validationJob = new TSLValidationJob();
        validationJob.setDataLoader(dataLoader);
        validationJob.setRepository(tslRepository);
        validationJob.setLotlUrl(lotlUrl);
        validationJob.setLotlCode(lotlCountryCode);
        validationJob.setOjUrl(currentOjUrl);
        validationJob.setOjContentKeyStore(ojContentKeyStore);
        validationJob.setCheckLOTLSignature(true);
        validationJob.setCheckTSLSignatures(true);
        return validationJob;
    }

}

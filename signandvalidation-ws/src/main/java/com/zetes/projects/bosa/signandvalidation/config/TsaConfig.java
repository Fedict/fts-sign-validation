package com.zetes.projects.bosa.signandvalidation.config;

import com.zetes.projects.bosa.signandvalidation.mocktsp.MockTSPSource;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.token.KeyStoreSignatureTokenConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;

@Configuration
public class TsaConfig {

    private static final Logger LOG = LoggerFactory.getLogger(TsaConfig.class);

    @Value("${tsa.mock}")
    private boolean mock;

    @Value("${tsa.server}")
    private String tsaServer;

    @Bean
    TSPSource tspSource() {
        if (mock) {
            MockTSPSource mockTSPSource = new MockTSPSource();
            try (InputStream is = new ClassPathResource("/self-signed-tsa.p12").getInputStream()) {
                mockTSPSource.setToken(new KeyStoreSignatureTokenConnection(is, "PKCS12", new KeyStore.PasswordProtection("ks-password".toCharArray())));
            } catch (IOException e) {
                LOG.warn("Cannot load the KeyStore");
            }
            mockTSPSource.setAlias("self-signed-tsa");
            return mockTSPSource;

        } else {
            return new OnlineTSPSource(tsaServer);
        }
    }

}

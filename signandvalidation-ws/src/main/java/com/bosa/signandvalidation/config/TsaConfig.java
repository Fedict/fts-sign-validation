package com.bosa.signandvalidation.config;

import com.bosa.signandvalidation.mocktsp.MockOnlineTSPSource;
import com.bosa.signandvalidation.dataloaders.InterceptTimestampDataLoader;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.http.proxy.ProxyConfig;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.token.KeyStoreSignatureTokenConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
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

    // can be null
    @Autowired(required = false)
    private ProxyConfig proxyConfig;

    @Bean
    OnlineTSPSource tspSource() {
        if (mock) {
            MockOnlineTSPSource mockTSPSource = new MockOnlineTSPSource();
            try (InputStream is = new ClassPathResource("/self-signed-tsa.p12").getInputStream()) {
                mockTSPSource.setToken(new KeyStoreSignatureTokenConnection(is, "PKCS12", new KeyStore.PasswordProtection("ks-password".toCharArray())));
            } catch (IOException e) {
                LOG.warn("Cannot load the KeyStore");
            }
            mockTSPSource.setAlias("self-signed-tsa");
            return mockTSPSource;

        } else {
            OnlineTSPSource onlineTSPSource = new OnlineTSPSource();
            TimestampDataLoader dataLoader = new InterceptTimestampDataLoader();
            dataLoader.setProxyConfig(proxyConfig);
            onlineTSPSource.setDataLoader(dataLoader);
            return onlineTSPSource;
        }
    }
}

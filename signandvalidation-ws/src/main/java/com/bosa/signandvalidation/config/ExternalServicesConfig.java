package com.bosa.signandvalidation.config;

import com.bosa.signandvalidation.service.RemoteSigningService;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.annotation.PropertySources;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;

@Configuration
public class ExternalServicesConfig {

    @Value("${getSadFromCode.url}")
    public String sadOpURL;
    @Value("${getCertificatesFromSad.url}")
    public String certificatesOpURL;
    @Value("${signDigestFromSad.url}")
    public String signDigestsOpURL;

    @Bean
    public RemoteSigningService remoteSigningService() {
        return new RemoteSigningService(sadOpURL, certificatesOpURL, signDigestsOpURL);
    }
}
package com.zetes.projects.bosa.signingconfigurator.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.transaction.PlatformTransactionManager;

import javax.sql.DataSource;
import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableJpaRepositories(
        basePackages = "com.zetes.projects.bosa.signingconfigurator.dao",
        entityManagerFactoryRef = "signingConfiguratorEMF",
        transactionManagerRef = "signingConfiguratorTM"
)
public class SigningConfiguratorPersistenceConfig {

    @Autowired
    private Environment env;

    @Bean
    public LocalContainerEntityManagerFactoryBean signingConfiguratorEMF() {
        LocalContainerEntityManagerFactoryBean em = new LocalContainerEntityManagerFactoryBean();
        em.setDataSource(signingConfiguratorDS());
        em.setPackagesToScan("com.zetes.projects.bosa.signingconfigurator.model");

        HibernateJpaVendorAdapter vendorAdapter = new HibernateJpaVendorAdapter();
        em.setJpaVendorAdapter(vendorAdapter);
        em.setJpaPropertyMap(addtionalProperties());

        return em;
    }

    @Bean
    public DataSource signingConfiguratorDS() {
        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName(env.getProperty("signingconfigurator.datasource.driver"));
        dataSource.setUrl(env.getProperty("signingconfigurator.datasource.url"));
        dataSource.setUsername(env.getProperty("signingconfigurator.datasource.username"));
        dataSource.setPassword(env.getProperty("signingconfigurator.datasource.password"));

        return dataSource;
    }

    @Bean
    public PlatformTransactionManager signingConfiguratorTM() {
        final JpaTransactionManager transactionManager = new JpaTransactionManager();
        transactionManager.setEntityManagerFactory(signingConfiguratorEMF().getObject());
        return transactionManager;
    }

    private Map<String, String> addtionalProperties() {
        HashMap<String, String> properties = new HashMap<>();
        properties.put("hibernate.show_sql", env.getProperty("signingconfigurator.hibernate.show_sql"));
        properties.put("hibernate.format_sql", env.getProperty("signingconfigurator.hibernate.format_sql"));
        properties.put("hibernate.hbm2ddl.auto", env.getProperty("signingconfigurator.hibernate.hbm2ddl.auto"));
        properties.put("hibernate.default_schema", env.getProperty("signingconfigurator.hibernate.default_schema"));
        properties.put("hibernate.dialect", env.getProperty("signingconfigurator.hibernate.dialect"));

        return properties;
    }

}

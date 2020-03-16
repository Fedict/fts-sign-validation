package com.zetes.projects.bosa.resourcelocator.config;

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
        basePackages = "com.zetes.projects.bosa.resourcelocator.dao",
        entityManagerFactoryRef = "resourceLocatorEMF",
        transactionManagerRef = "resourceLocatorTM"
)
public class ResourceLocatorPersistenceConfig {

    @Autowired
    private Environment env;

    @Bean
    public LocalContainerEntityManagerFactoryBean resourceLocatorEMF() {
        LocalContainerEntityManagerFactoryBean em = new LocalContainerEntityManagerFactoryBean();
        em.setDataSource(resourceLocatorDS());
        em.setPackagesToScan("com.zetes.projects.bosa.resourcelocator.model");

        HibernateJpaVendorAdapter vendorAdapter = new HibernateJpaVendorAdapter();
        em.setJpaVendorAdapter(vendorAdapter);
        em.setJpaPropertyMap(addtionalProperties());

        return em;
    }

    @Bean
    public DataSource resourceLocatorDS() {
        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName(env.getProperty("resourcelocator.datasource.driver"));
        dataSource.setUrl(env.getProperty("resourcelocator.datasource.url"));
        dataSource.setUsername(env.getProperty("resourcelocator.datasource.username"));
        dataSource.setPassword(env.getProperty("resourcelocator.datasource.password"));

        return dataSource;
    }

    @Bean
    public PlatformTransactionManager resourceLocatorTM() {
        final JpaTransactionManager transactionManager = new JpaTransactionManager();
        transactionManager.setEntityManagerFactory(resourceLocatorEMF().getObject());
        return transactionManager;
    }

    private Map<String, String> addtionalProperties() {
        HashMap<String, String> properties = new HashMap<>();
        properties.put("hibernate.show_sql", env.getProperty("resourcelocator.hibernate.show_sql"));
        properties.put("hibernate.format_sql", env.getProperty("resourcelocator.hibernate.format_sql"));
        properties.put("hibernate.hbm2ddl.auto", env.getProperty("resourcelocator.hibernate.hbm2ddl.auto"));
        properties.put("hibernate.default_schema", env.getProperty("resourcelocator.hibernate.default_schema"));
        properties.put("hibernate.dialect", env.getProperty("resourcelocator.hibernate.dialect"));

        return properties;
    }

}

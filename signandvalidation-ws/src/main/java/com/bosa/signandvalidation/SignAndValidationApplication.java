package com.bosa.signandvalidation;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

@SpringBootApplication
public class SignAndValidationApplication {

    private static ConfigurableApplicationContext context;
    public static void main(String[] args) {
        context = SpringApplication.run(SignAndValidationApplication.class, args);
    }

    public static void stop() {
        context.stop();
    }
}

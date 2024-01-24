package com.bosa.signandvalidation.config;

import org.springdoc.core.SpringDocUtils;
import org.springframework.context.annotation.Configuration;

/*
    Springdoc maps the Jave "byte bytes[]" as "bytes": [ "string" ] in the Json definition or as the YAML below

        bytes:
          type: array
          items:
            type: string
            format: byte

    This configuration aims to fix this by replacing all "byte []" by Strings.
 */
@Configuration
public class SpringDocByteArrayFixer {
    static {
        SpringDocUtils.getConfig().replaceWithClass(byte[].class, String.class);
    }
}

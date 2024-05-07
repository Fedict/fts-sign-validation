package com.bosa.signandvalidation.config;

import io.swagger.v3.oas.models.media.Schema;
import org.springdoc.core.SpringDocUtils;
import org.springframework.context.annotation.Configuration;

/*
    Springdoc maps the Jave "byte bytes[]" as "bytes": [ "string" ] in the Json definition or as the YAML below

        bytes:
          type: array
          items:
            type: string
            format: byte

    This configuration aims to fix this by replacing all "byte []" by string with format "byte".
 */
@Configuration
public class SpringDocByteArrayFixer {
    static {
        SpringDocUtils.getConfig().replaceWithSchema(byte[].class, new Schema<byte[]>().type("string").format("byte"));
    }
}

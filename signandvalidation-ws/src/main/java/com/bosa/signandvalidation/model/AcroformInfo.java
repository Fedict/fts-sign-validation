package com.bosa.signandvalidation.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AcroformInfo {
    private float width; // When drawing a V1 & V3 Visible signature the width & height are needed, ...
    private float height; // ... the preflight validation done at token creation saves the dimensions in the token store for performance
}

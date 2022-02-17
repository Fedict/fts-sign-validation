package com.zetes.projects.bosa.signandvalidation.model;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Setter
@Getter
@NoArgsConstructor
public class FileInfoForTokenDTO {
    private List<String> nnAllowedToSign;
    private List<SignInput> inputs;
}

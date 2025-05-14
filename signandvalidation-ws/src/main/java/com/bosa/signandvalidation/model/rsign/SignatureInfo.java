package com.bosa.signandvalidation.model.rsign;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

@Getter
@AllArgsConstructor
public class SignatureInfo {
    private SigningAccountStatus signAccountstatus;
    private int maxSignatures;
    private byte[] signingCertificate;
    private List<byte[]> certificateChain;
}

package com.bosa.signandvalidation.model.remotesign;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class RemoteCertInfo {
    private String status;
    private List<byte []> certificates;
    private String issuerDN;
    private String serialNumber;
    private String subjectDN;
    private String validFrom;
    private String validTo;
}

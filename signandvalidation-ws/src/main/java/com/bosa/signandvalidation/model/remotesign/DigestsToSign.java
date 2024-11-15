package com.bosa.signandvalidation.model.remotesign;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class DigestsToSign {
    private DigestAlgorithm digestAlgorithm;
    private List<byte[]> digests = new ArrayList<>();

    public DigestsToSign(DigestAlgorithm digestAlgorithm, byte[] digest) {
        this.digestAlgorithm = digestAlgorithm;
        this.digests.add(digest);
    }
}

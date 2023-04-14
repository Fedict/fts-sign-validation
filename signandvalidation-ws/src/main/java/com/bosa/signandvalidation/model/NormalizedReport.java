package com.bosa.signandvalidation.model;

import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class NormalizedReport {
    List<NormalizedSignatureInfo> signatures = new ArrayList<>();
}

package com.bosa.signandvalidation.model.remotesign;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class RemoteKeyInfo {
    private String status;
    private List<String> algo;
    private Integer len;
    private String curve;
}

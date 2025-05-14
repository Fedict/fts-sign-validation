package com.bosa.signandvalidation.model.rsign;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class SignedHashes {
    List<byte []> signatures;
}

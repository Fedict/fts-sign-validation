package com.bosa.signandvalidation.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.concurrent.CompletableFuture;

@Setter
@Getter
@NoArgsConstructor
public class TaskOutcomeDTO {
    private Exception exception;
    private Object result;
}

package com.bosa.signandvalidation.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.concurrent.CompletableFuture;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class TaskOutcomeDTO {
    private boolean completed;
    private Exception exception;
    private Object result;

    public TaskOutcomeDTO(CompletableFuture<Object> task) {
        this.completed = task.isDone();
        if (task.isCompletedExceptionally())
    }
}

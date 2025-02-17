package com.bosa.signandvalidation.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ASyncTaskStatusDTO {
    public static final ASyncTaskStatusDTO DONE = new ASyncTaskStatusDTO(true);
    public static final ASyncTaskStatusDTO RUNNING = new ASyncTaskStatusDTO(false);

    private Boolean done;
}

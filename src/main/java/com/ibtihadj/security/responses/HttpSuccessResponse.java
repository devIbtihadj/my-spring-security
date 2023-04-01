package com.ibtihadj.security.responses;

import lombok.*;
import org.springframework.http.HttpStatus;

@Setter
@Getter
@Data
@RequiredArgsConstructor
@AllArgsConstructor
public class HttpSuccessResponse {

    private HttpStatus status;

    private int statusCode;

    private String message;

    private Object data;
}

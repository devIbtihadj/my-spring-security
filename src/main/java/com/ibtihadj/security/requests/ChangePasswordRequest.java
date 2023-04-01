package com.ibtihadj.security.requests;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;


@Setter
@Getter
@RequiredArgsConstructor
@Data
public class ChangePasswordRequest {

    @NotNull
    @NotBlank
    private String token;

    @NotNull
    @NotBlank
    private String password;
}

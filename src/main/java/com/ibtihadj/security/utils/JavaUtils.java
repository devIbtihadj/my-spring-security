package com.ibtihadj.security.utils;

import com.ibtihadj.security.responses.HttpSuccessResponse;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.Random;

@Component
public class JavaUtils {

    public final int ITERATION = 10000;
    private final Random RANDOM = new SecureRandom();
    public final String ALPHABET = "0123456789AZERTYUIOPQSDFGHJKLMWXCVBNazertyuiopqsdfghjklmwxcvbn";

    public final String SPECIALCHARACTERS = "~!@#$%^&*_-+='|\\(){}[]:;\"' <>,.? /";

    public final String CHIFFRES="0123456789";

    public final String MAJUSCULES = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    public final String MINUSCULES = "abcdefghijklmnopqrstuvwxyz";

    private final int KEY_LENGTH = 256;

    public String generateString(int length) {
        return generateRandomString(length);
    }

    public String generateRandomString(int length) {
        StringBuilder value = new StringBuilder(length);

        for (int i = 0; i < length; i++) {
            value.append(ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
        }

        return new String(value);
    }

    public static HttpSuccessResponse successResponse(HttpStatus status, String message, Object... data) {
        HttpSuccessResponse response = new HttpSuccessResponse();
        response.setStatus(status);
        response.setMessage(message);
        response.setStatusCode(status.value());
        response.setData(data);
        return response;
    }
}

package com.ibtihadj.security.exceptions;

public class UserAlreadyExistException extends Exception{

    public UserAlreadyExistException(String message) {
        super(message);
    }
}

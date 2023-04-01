package com.ibtihadj.security.controllers;

import com.ibtihadj.security.exceptions.*;
import com.ibtihadj.security.handlers.ExceptionsHandler;
import com.ibtihadj.security.requests.ChangePasswordRequest;
import com.ibtihadj.security.requests.ForgetPassordRequest;
import com.ibtihadj.security.requests.LoginRequest;
import com.ibtihadj.security.requests.RegisterRequest;
import com.ibtihadj.security.responses.HttpSuccessResponse;
import com.ibtihadj.security.responses.JwtResponse;
import com.ibtihadj.security.services.UserService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.mail.MessagingException;
import java.io.UnsupportedEncodingException;

import static com.ibtihadj.security.utils.constants.JavaConstant.API_BASE_URL;
import static org.springframework.http.HttpStatus.CREATED;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.http.MediaType.APPLICATION_XML_VALUE;

@RestController
@RequestMapping(API_BASE_URL)
public class AuthController extends ExceptionsHandler {

    private final String ENTITY_URL_NAME = "auth";
    private final UserService userService;

    @Autowired
    public AuthController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping(value = ENTITY_URL_NAME+"/register", consumes = {APPLICATION_JSON_VALUE, APPLICATION_XML_VALUE},
            produces = {APPLICATION_JSON_VALUE, APPLICATION_XML_VALUE})
    public ResponseEntity<HttpSuccessResponse> register(@RequestBody @Valid RegisterRequest request) throws RoleNotFoundException, UserAlreadyExistException, ParametreNotValidate, RoleAlreadyExistException {
        HttpSuccessResponse response = userService.storeUser(request);
        return ResponseEntity.status(CREATED).body(response);
    }

    @PostMapping(value = ENTITY_URL_NAME+"/login", consumes = {APPLICATION_JSON_VALUE, APPLICATION_XML_VALUE},
            produces = {APPLICATION_JSON_VALUE, APPLICATION_XML_VALUE})
    public ResponseEntity<JwtResponse> login(@RequestBody @Valid LoginRequest request)throws UserNotFoundException
    {
        System.out.println(request+"***************************************");
        JwtResponse response = new JwtResponse();
        String token = userService.authenticate(request);
        response.setAccess_token(token);
        return ResponseEntity.ok().body(response);
    }

    @PostMapping(value = ENTITY_URL_NAME+"/me", produces = {APPLICATION_JSON_VALUE, APPLICATION_XML_VALUE})
    public ResponseEntity<HttpSuccessResponse> me() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        HttpSuccessResponse response = userService.authUser(authentication);
        return ResponseEntity.ok().body(response);
    }

    @PostMapping(value = ENTITY_URL_NAME+"/forget_password",
            produces = {APPLICATION_JSON_VALUE, APPLICATION_XML_VALUE})
    public ResponseEntity<HttpSuccessResponse> forget_password(HttpServletRequest servletRequest, @RequestBody @Valid ForgetPassordRequest request) throws MessagingException, UnsupportedEncodingException, UserNotFoundException, jakarta.mail.MessagingException {
        System.out.println("---------------------Je suis là");
        HttpSuccessResponse response = userService.onGet_password_Token(servletRequest, request.getEmail());
        return ResponseEntity.status(OK).body(response);
    }

    @PostMapping(value = ENTITY_URL_NAME+"/change_password",
            produces = {APPLICATION_JSON_VALUE, APPLICATION_XML_VALUE})
    public ResponseEntity<HttpSuccessResponse> change_password(@RequestBody @Valid ChangePasswordRequest request) throws MessagingException, UnsupportedEncodingException, UserNotFoundException, ParametreNotValidate {
        System.out.println("---------------------Je suis là");
        HttpSuccessResponse response = userService.changePasswordRequest(request);
        return ResponseEntity.status(OK).body(response);
    }


    @GetMapping(value = ENTITY_URL_NAME+"/users",
            produces = {APPLICATION_JSON_VALUE, APPLICATION_XML_VALUE})
    public ResponseEntity<HttpSuccessResponse> allUsers() {
        System.out.println("---------------------Je suis là");
        HttpSuccessResponse response = userService.allUser();
        return ResponseEntity.status(OK).body(response);
    }


}

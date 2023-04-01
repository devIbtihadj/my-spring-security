package com.ibtihadj.security.services.implementations;

import com.ibtihadj.security.entities.Parametre;
import com.ibtihadj.security.entities.Role;
import com.ibtihadj.security.entities.User;
import com.ibtihadj.security.exceptions.*;
import com.ibtihadj.security.repositories.ParametreRepository;
import com.ibtihadj.security.repositories.RoleRepository;
import com.ibtihadj.security.repositories.UserRepository;
import com.ibtihadj.security.requests.ChangePasswordRequest;
import com.ibtihadj.security.requests.LoginRequest;
import com.ibtihadj.security.requests.RegisterRequest;
import com.ibtihadj.security.responses.HttpSuccessResponse;
import com.ibtihadj.security.services.UserService;
import com.ibtihadj.security.utils.JavaConverter;
import com.ibtihadj.security.utils.JavaUtils;
import com.ibtihadj.security.utils.JwtUtils;
import com.ibtihadj.security.utils.UserPrincipal;
import jakarta.mail.internet.MimeMessage;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.mail.MessagingException;
import java.io.UnsupportedEncodingException;
import java.util.List;
import java.util.Optional;

import static com.ibtihadj.security.utils.JavaUtils.successResponse;
import static org.springframework.http.HttpStatus.CREATED;
import static org.springframework.http.HttpStatus.OK;

@Service
@Transactional
public class UserServiceImplementation implements UserService {

    @Value("${client.address}")
    private String frontendServerURL;
    private final JavaMailSender javaMailSender;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final JwtUtils jwtUtils;
    private final JavaUtils javaUtils;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JavaConverter javaConverter;
    private final ParametreRepository parametreRepository;

    public UserServiceImplementation(JavaMailSender javaMailSender, UserRepository userRepository, RoleRepository roleRepository, JwtUtils jwtUtils, JavaUtils javaUtils, BCryptPasswordEncoder bCryptPasswordEncoder, AuthenticationManager authenticationManager, JavaConverter javaConverter, ParametreRepository parametreRepository) {
        this.javaMailSender = javaMailSender;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.jwtUtils = jwtUtils;
        this.javaUtils = javaUtils;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.authenticationManager = authenticationManager;
        this.javaConverter = javaConverter;
        this.parametreRepository = parametreRepository;
    }

    @Override
    public HttpSuccessResponse storeUser(RegisterRequest request) throws RoleNotFoundException, UserAlreadyExistException, RoleAlreadyExistException, ParametreNotValidate {

        validateAllParamtres(request.getPassword());
        request.setPassword(bCryptPasswordEncoder.encode(request.getPassword()));


        Optional<User> userAvecMail = userRepository.findByEmail(request.getEmail());
        Optional<User> userAvecUsername = userRepository.findByUsername(request.getUsername());

        if(userAvecMail.isPresent()){
            throw new UserAlreadyExistException("Un utilisateur avec cette adresse email est déja enrégistré");
        }
        if(userAvecUsername.isPresent()){
            throw new UserAlreadyExistException("Un utilisateur avec ce nom d'utilisateur est déja enrégistré");
        }

        User user = userRepository.save(javaConverter.registerToUser(request));

        if(request.getInitRoles()==null){
            addRoleToUser("ROLE_USER", request.getUsername());
        }else {
            for (Role role: request.getInitRoles()){
                addRoleToUser(role.getName(), request.getUsername());
            }
        }

        return successResponse(CREATED, "Votre compte a bien été créer.", javaConverter.userToUserResponse(user));
    }

    @Override
    public HttpSuccessResponse authUser(Authentication authentication) {
        String username = authentication.getName();
        Optional<User> user = userRepository.findByUsername(username);
        user.orElseThrow(() -> new UsernameNotFoundException("Utilisateur Non trouvée!"));
        return successResponse(OK, "Détails du compte de l'utilisateur", user.map(javaConverter::userToUserResponse));
    }

    @Override
    public void addRoleToUser(String roleName, String username) throws RoleNotFoundException, RoleAlreadyExistException {
        Optional<Role> role = roleRepository.findByName(roleName);
        role.orElseThrow(() -> new RoleNotFoundException("Role n'existe pas"));
        Optional<User> user = userRepository.findByUsername(username);
        if(user.isPresent()){
            for (Role r: user.get().getRoles()) {
                if(r.getId().equals(role.get().getId())){
                    throw new RoleAlreadyExistException("Ce role existe déjà pour cet utilisateur");
                }
            }
        }
        user
                .orElseThrow(() -> new UsernameNotFoundException("Utilisateur n'existe pas"))
                .getRoles()
                .add(role.get());
        userRepository.save(user.get());
    }

    @Override
    public HttpSuccessResponse changePasswordRequest(ChangePasswordRequest request) throws ParametreNotValidate, UserNotFoundException {

        Optional<User> optionalUser= userRepository.findBytoken(request.getToken());

        if(optionalUser.isEmpty()){
            throw new UserNotFoundException("Token invalid. Veuillez cliquez sur le lien envoyé par email " +
                    "pour envoyer votre requête");
        }
        validateAllParamtres(request.getPassword());
        optionalUser.get().setPassword(bCryptPasswordEncoder.encode(request.getPassword()));
        userRepository.save(optionalUser.get());

        return successResponse(CREATED, "Votre mot de passe a bien été mis à jour.", javaConverter.userToUserResponse(optionalUser.get()));
    }

    @Override
    public HttpSuccessResponse allUser() {

        List<User> all = userRepository.findAll();

        return new HttpSuccessResponse(OK, 200, "Récupération des utilisateurs réussi", all);
    }

    @Override
    public String authenticate(LoginRequest request) throws UserNotFoundException {

        Optional<User> user = userRepository.findByUsername(request.getUsername());
        user.orElseThrow(() -> new UserNotFoundException("Aucun utilisateur n'existe avec cet nom d'utilisateur!"));
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );
        System.out.println("---------------------after authenticate");
        System.out.println("---------------------here");
        return jwtUtils.generateToken(user.map(UserPrincipal::new).get());

    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> user = userRepository.findByUsername(username);
        user.orElseThrow(() -> new UsernameNotFoundException("Utilisateur n'existe pas dans la base."));
        return user.map(UserPrincipal::new).get();
    }

    @Override
    public UserDetails loadByEmail(String email) throws UsernameNotFoundException {
        Optional<User> user = userRepository.findByEmail(email);
        user.orElseThrow(() -> new UsernameNotFoundException("Utilisateur n'existe pas dans la base."));
        return user.map(UserPrincipal::new).get();
    }

    @Override
    public HttpSuccessResponse onGet_password_Token(HttpServletRequest servletRequest,String userEmail) throws MessagingException, UnsupportedEncodingException, UserNotFoundException, jakarta.mail.MessagingException {

        Optional<User> optionalUser = userRepository.findByEmail(userEmail);

        if(optionalUser.isEmpty()){
            throw new UserNotFoundException("Aucun utilisateur n'existe avec cette adresse email");
        }

        String token = javaUtils.generateRandomString(45);
        optionalUser.get().setReset_password_token(token);
        userRepository.save(optionalUser.get());
        String siteUrl = servletRequest.getRequestURL().toString();
        String realSiteUrl = siteUrl.replace(servletRequest.getServletPath(), "");

        System.out.println("----------------------------------------REMOTEADDTR"+servletRequest.getRemoteAddr());

        //String resetPasswordLink = realSiteUrl+"/reset_password?token="+token;

        String resetPasswordLink = frontendServerURL+"/reset_password?token="+token;

        System.out.println("-------------------------------------------------------ResetPwdLink "+resetPasswordLink);

        MimeMessage message = javaMailSender.createMimeMessage();
        System.out.println("------------------- mime message created");
        MimeMessageHelper helper = new MimeMessageHelper(message);

        helper.setFrom("ibtihadjpro@gmail.com", "KIVEH IMMO");
        helper.setTo(userEmail);

        String subject = "Votre lien de modification de mot de passe";

        /*String content = "<p>Bonjour,</p>" +
                "<p>Vous aviez fait une demande de modification de mot de passe</p>"+
                "<p>Cliquez sur le lien ci-dessous pour continuer le processus.</p>"+
                "<a href=\""+resetPasswordLink+"\">Changer mon mot de passe</a>"+"."+
                "<p></br> Ignorez simplement cet email si vous n'aviez fait aucune demande.</p>";*/

        String content = "<p>Bonjour,</p>" +
                "<p>Vous aviez fait une demande de modification de mot de passe</p>"+
                "<p>Cliquez sur le lien ci-dessous pour continuer le processus.</p>"+
                "<a href=\""+resetPasswordLink+"\">Changer mon mot de passe</a>"+
                "<p>Ignorez simplement cet email si vous n'aviez fait aucune demande.</p>";



        helper.setSubject(subject);
        helper.setText(content, true);

        javaMailSender.send(message);

        return successResponse(OK, "Token généré", token);
    }


    public boolean validerParametre1(String userPassword) throws ParametreNotValidate {
        if(parametreRepository.checkParametre(1).isEtat()){
            Parametre parametre = parametreRepository.checkParametre(1);
            if(userPassword.length() >= parametre.getTaille()){
                return true;
            }else {
                throw new ParametreNotValidate("La taille du mot de passe n'est pas respectée : Il en faut "+parametre.getTaille());
            }
        }else {
            return true;
        }
    }

    public boolean validerParametre2(String userPassword) throws ParametreNotValidate {
        System.out.println("--------------------------------------Check parametre 2");
        if(parametreRepository.checkParametre(2).isEtat()){
            Parametre parametre = parametreRepository.checkParametre(2);
            int specialTaillePassword = 0;
            for(int i=0; i<userPassword.length(); i++){
                for (int j=0; j<javaUtils.SPECIALCHARACTERS.length(); j++){
                    if(userPassword.contains(String.valueOf(javaUtils.SPECIALCHARACTERS.charAt(j)))){
                        specialTaillePassword = specialTaillePassword + 1;
                    }
                }

            }
            if(specialTaillePassword >= parametre.getTaille()){
                return true;
            }else {
                throw new ParametreNotValidate("Le nombre de caractères spéciaux n'a pas été respecté : Il en faut au minimum "+parametre.getTaille());
            }
        }else {
            return true;
        }
    }

    public boolean validerParametre3(String userPassword) throws ParametreNotValidate {
        System.out.println("--------------------------------------Check parametre 3");
        if(parametreRepository.checkParametre(3).isEtat()){
            Parametre parametre = parametreRepository.checkParametre(3);
            int nbrChiffres = 0;

            for(int i=0; i<userPassword.length(); i++){
                for (int j=0; j<javaUtils.CHIFFRES.length(); j++){
                    if(userPassword.contains(String.valueOf(javaUtils.CHIFFRES.charAt(j)))){
                        nbrChiffres = nbrChiffres + 1;
                    }
                }

            }
            if(nbrChiffres >= parametre.getTaille()){
                return true;
            }else {
                throw new ParametreNotValidate("Le nombre de chiffres n'a pas été respecté : Il en faut au minimum "+parametre.getTaille());
            }

        }else {
            return true;
        }
    }

    public boolean validerParametre4(String userPassword) throws ParametreNotValidate {
        if(parametreRepository.checkParametre(4).isEtat()){
            Parametre parametre = parametreRepository.checkParametre(4);
            int nbrMajucules = 0;

            for(int i=0; i<userPassword.length(); i++){
                for (int j=0; j<javaUtils.MAJUSCULES.length(); j++){
                    if(userPassword.contains(String.valueOf(javaUtils.MAJUSCULES.charAt(j)))){
                        nbrMajucules = nbrMajucules + 1;
                    }
                }

            }
            if(nbrMajucules >= parametre.getTaille()){
                return true;
            }else {
                throw new ParametreNotValidate("Le nombre de lettres majuscules n'a pas été respecté : Il en faut au minimum "+parametre.getTaille());
            }

        }else {
            return true;
        }
    }

    public boolean validerParametre5(String userPassword) throws ParametreNotValidate {
        if(parametreRepository.checkParametre(5).isEtat()){
            Parametre parametre = parametreRepository.checkParametre(5);
            int nbrMinuccules = 0;

            for(int i=0; i<userPassword.length(); i++){
                for (int j=0; j<javaUtils.MINUSCULES.length(); j++){
                    if(userPassword.contains(String.valueOf(javaUtils.MINUSCULES.charAt(j)))){
                        nbrMinuccules = nbrMinuccules + 1;
                    }
                }

            }
            if(nbrMinuccules >= parametre.getTaille()){
                return true;
            }else {
                throw new ParametreNotValidate("Le nombre de lettres minuscules n'a pas été respecté : Il en faut au minimum "+parametre.getTaille());
            }

        }else {
            return true;
        }
    }

    public boolean validateAllParamtres(String userPassword) throws ParametreNotValidate {
        return validerParametre1(userPassword) &&
                validerParametre2(userPassword) &&
                validerParametre3(userPassword) &&
                validerParametre4(userPassword) &&
                validerParametre5(userPassword);
    }
}

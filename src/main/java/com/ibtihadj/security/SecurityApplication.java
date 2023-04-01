package com.ibtihadj.security;

import com.ibtihadj.security.entities.Parametre;
import com.ibtihadj.security.entities.Role;
import com.ibtihadj.security.repositories.ParametreRepository;
import com.ibtihadj.security.repositories.RoleRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
public class SecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityApplication.class, args);
	}


//	@Bean
//	public CommandLineRunner runner(ParametreRepository parametreRepository, RoleRepository roleRepository) {
//		return args -> {
//			Parametre parametre1 = new Parametre("longueur", 8);
//			parametreRepository.save(parametre1);
//			Parametre parametre2 = new Parametre("caractères spéciaux", 1);
//			parametreRepository.save(parametre2);
//			Parametre parametre3 = new Parametre("chiffres",1);
//			parametreRepository.save(parametre3);
//			Parametre parametre4 = new Parametre("majuscules",1);
//			parametreRepository.save(parametre4);
//			Parametre parametre5 = new Parametre("miniscule",1);
//			parametreRepository.save(parametre5);
//
//			Role role1 = new Role("ROLE_ADMIN");
//			roleRepository.save(role1);
//			Role role2 = new Role("ROLE_USER");
//			roleRepository.save(role2);
//
//
//		};
//
//	}

}

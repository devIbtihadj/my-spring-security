package com.ibtihadj.security.entities;

import lombok.*;

import jakarta.persistence.*;
import java.io.Serializable;

@Builder
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Entity
@Table(name = "parametres")
public class Parametre implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(nullable = false, unique = true)
    private String libelle;


    private long taille;

    @Column(nullable = false)
    private boolean etat = true;

    public Parametre(String libelle, long taille) {
        this.libelle = libelle;
        this.taille = taille;
    }

}

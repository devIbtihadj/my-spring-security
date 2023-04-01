package com.ibtihadj.security.repositories;

import com.ibtihadj.security.entities.Parametre;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ParametreRepository extends JpaRepository<Parametre, Long> {

    @Query("SELECT p FROM Parametre p WHERE p.id=:X")
    Parametre checkParametre(@Param("X") long id);
}
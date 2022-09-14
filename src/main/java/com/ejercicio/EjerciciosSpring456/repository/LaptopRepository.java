package com.ejercicio.EjerciciosSpring456.repository;

import com.ejercicio.EjerciciosSpring456.entities.Laptop;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface LaptopRepository extends JpaRepository<Laptop,Long> {
}

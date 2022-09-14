package com.ejercicio.EjerciciosSpring456.controllers;

import com.ejercicio.EjerciciosSpring456.entities.Laptop;
import com.ejercicio.EjerciciosSpring456.repository.LaptopRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
public class LaptopController {
    //Atributos
    @Value("${app.message}")
    String message;
    @Value("${app.varexample}")
    String user;
    private LaptopRepository repositoryLap;
    //Constructores

    public LaptopController(LaptopRepository repositoryLap) {
        this.repositoryLap = repositoryLap;
    }
    //Métodos
    //Obtener todos los objetos Laptop de la BBDD
    @GetMapping("/api/laptops")
    public List<Laptop> findAll(){
        System.out.println("Welcome " + user);
        System.out.println(message);
        return repositoryLap.findAll();
    }

    //Obtener un objeto por su Id
    @GetMapping("/api/laptops/{id}")
    public ResponseEntity<Laptop> findOneById(@PathVariable Long id){
        Optional<Laptop> lapFinding = repositoryLap.findById(id);
        if(lapFinding.isPresent())
            return ResponseEntity.ok(lapFinding.get());
        else
            return ResponseEntity.notFound().build();
    }

    //Crear un nuevo objeto Laptop a partir de una petición POST http
    @PostMapping("/api/laptops")
    public Laptop create(@RequestBody Laptop laptop){
        return repositoryLap.save(laptop);
    }

    //Actualizar un objeto
    @PutMapping("/api/laptops")
    public ResponseEntity<Laptop> update(@RequestBody Laptop laptop){
        //Comprobación de intento de creación, no actualización
        if (laptop.getId() == null)
            return ResponseEntity.badRequest().build();
        //Comprobación de intento de actualizar una laptop no existente
        if (!repositoryLap.existsById(laptop.getId()))
            return ResponseEntity.badRequest().build();
        //Actualización
        Laptop updated = repositoryLap.save(laptop);
        return ResponseEntity.ok(updated);
    }

    //Borrar un objeto por Id
    @DeleteMapping("/api/laptops/{id}")
    public ResponseEntity<Laptop> delete(@PathVariable Long id){
        //Comprobación de intento de borrar una laptop que no existe
        if(!repositoryLap.existsById(id))
            return ResponseEntity.notFound().build();
        //Borrado
        repositoryLap.deleteById(id);
        return ResponseEntity.noContent().build();
    }

    //Borrar todos los objetos
    @DeleteMapping("/api/laptops")
    public ResponseEntity<Laptop> deleteAll(){
        //Borrar todos los registros
        repositoryLap.deleteAll();
        return ResponseEntity.noContent().build();
    }
}
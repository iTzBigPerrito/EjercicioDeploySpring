package com.ejercicio.EjerciciosSpring456.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/saludo")
    public String sayHi(){
        return "Hola, soy una API REST";
    }
}

package com.ejercicio.EjerciciosSpring456.controllers;

import com.ejercicio.EjerciciosSpring456.entities.Laptop;
import com.ejercicio.EjerciciosSpring456.repository.LaptopRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.*;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class LaptopControllerTest {

    private TestRestTemplate testRestTemplate;
    @Autowired
    private RestTemplateBuilder restTemplateBuilder;

    @LocalServerPort
    private int port;

    @Autowired
    private LaptopRepository repository;

    @BeforeEach
    void setUp() {
        restTemplateBuilder = restTemplateBuilder.rootUri("http://localhost:" + port);
        testRestTemplate = new TestRestTemplate(restTemplateBuilder);
        Laptop laptop1 = new Laptop(null,"Asus","Stinger",1500.73,true);
        Laptop laptop2 = new Laptop(null,"HP","H2B455",450.99,true);
        Laptop laptop3 = new Laptop(null,"ROG","LROG3090",1090.55,false);
        repository.save(laptop1);
        repository.save(laptop2);
        repository.save(laptop3);
    }

    @DisplayName("Comprobar que se obtienen todos los registros desde el controlador de Laptops")
    @Test
    void findAll() {
        ResponseEntity response =
                testRestTemplate.getForEntity("/api/laptops", String.class);
        assertEquals(HttpStatus.OK,response.getStatusCode());
    }

    @Test
    void findOneById() {
        ResponseEntity response =
                testRestTemplate.getForEntity("/api/laptops/2",String.class);
        assertEquals(HttpStatus.OK,response.getStatusCode());
        response = testRestTemplate.getForEntity("/api/laptops/599",String.class);
        assertEquals(HttpStatus.NOT_FOUND,response.getStatusCode());
    }

    @Test
    void create() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

        String json = """
                {
                    "marca": "Laptop creada desde Spring Test",
                    "modelo": "Modelo Prueba Spring Test",
                    "precio": 190.55,
                    "disponibilidad": true
                }
                """;

        HttpEntity<String> request = new HttpEntity<>(json,headers);
        ResponseEntity<Laptop> response =
                testRestTemplate.exchange("/api/laptops",HttpMethod.POST,request,Laptop.class);
        Laptop result = response.getBody();
        assertEquals(4L,result.getId());
        assertEquals("Laptop creada desde Spring Test",result.getMarca());
    }

    @Test
    void update() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

        String json = """
                {
                    "id": 2,
                    "marca": "Laptop actualizada desde Spring Test",
                    "modelo": "Modelo actualizado Spring Test",
                    "precio": 200.52,
                    "disponibilidad": false
                }
                """;
        HttpEntity<String> request = new HttpEntity<>(json,headers);
        ResponseEntity<Laptop> response =
                testRestTemplate.exchange("/api/laptops",HttpMethod.PUT,request, Laptop.class);
        Laptop result = response.getBody();
        assertEquals("Laptop actualizada desde Spring Test",result.getMarca());
        assertEquals(HttpStatus.OK,response.getStatusCode());
    }

    @Test
    void delete() {
        boolean found = repository.existsById(1L);
        if (found){
            System.out.println(repository.findAll().size());
            testRestTemplate.delete("/api/laptops/1");
            found = repository.existsById(1L);
        }
        assertFalse(found);
        System.out.println(repository.findAll().size());
    }

    @Test
    void deleteAll() {
        boolean wiped = false;
        System.out.println(repository.count());
        testRestTemplate.delete("/api/laptops");
        /*Prueba con error a proposito para asegurar que todos los registros han sido eliminados.

        Laptop laptop1 = new Laptop(null,"Asus","Stinger",1500.73,true);
        repository.save(laptop1);
        */
        if(repository.count()==0)
            wiped = true;
        System.out.println(repository.count());
        assertTrue(wiped);
    }
}
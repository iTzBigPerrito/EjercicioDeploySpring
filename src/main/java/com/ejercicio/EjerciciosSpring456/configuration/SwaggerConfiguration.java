package com.ejercicio.EjerciciosSpring456.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.Contact;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;

import java.util.Collections;

/** Configuración de Swagger para este proyecto
 *  HTML:http://localhost:8080/swagger-ui/
 *  JSON:http://localhost:8080/v2/api-docs
 */
@Configuration
public class SwaggerConfiguration {

    @Bean
    public Docket api(){
        return new Docket(DocumentationType.SWAGGER_2)
                .apiInfo(apiDetails())
                .select()
                .apis(RequestHandlerSelectors.any())
                .paths(PathSelectors.any())
                .build();
    }

    public ApiInfo apiDetails(){
        return new ApiInfo("Ejercicio Spring Boot API REST",
                "Ejercicios sesiones 7, 8 y 9 Open Bootcamp",
                "1.0",
                "http://open-bootcamp.com/",new Contact("Daniel","https://github.com/iTzBigPerrito","byrdanto@gmail.com"),
                "Creative Commons",
                "https://creativecommons.org/",
                Collections.emptyList());
    }
}
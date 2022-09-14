package com.ejercicio.EjerciciosSpring456;

import com.ejercicio.EjerciciosSpring456.entities.Laptop;
import com.ejercicio.EjerciciosSpring456.repository.LaptopRepository;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;

@SpringBootApplication
public class EjerciciosSpring456Application {

	public static void main(String[] args) {
		ApplicationContext context = SpringApplication.run(EjerciciosSpring456Application.class, args);
		// Repositorio de Laptop que se obtiene de ApplicationContext (contenedor de Beans)
		LaptopRepository repository = context.getBean(LaptopRepository.class);

		// Creación de Objetos Laptop
		Laptop laptop1 = new Laptop(null,"Asus","Stinger",1500.73,true);
		Laptop laptop2 = new Laptop(null,"HP","H2B455",450.99,true);
		Laptop laptop3 = new Laptop(null,"ROG","LROG3090",1090.55,false);

		// Inserción de datos a la BBDD H2 con el repositorio
		System.out.println("Cantidad de laptops en BBDD: " + repository.findAll().size());
		repository.save(laptop1);
		repository.save(laptop2);
		repository.save(laptop3);
		System.out.println("Cantidad de laptops en BBDD: " + repository.findAll().size());

	}
}

package com.lk.config;


import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

	@Bean
	public OpenAPI openApiConfiguration(){
		return new OpenAPI()
				.info(new Info()
						.title("Spring Jwt Security")
						.version("0.0.1")
						.description("Spring Jwt Security")
				);
	}
	
}

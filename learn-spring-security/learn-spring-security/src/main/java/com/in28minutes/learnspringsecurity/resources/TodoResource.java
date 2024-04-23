package com.in28minutes.learnspringsecurity.resources;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import jakarta.annotation.security.RolesAllowed;

@RestController
public class TodoResource {
	
	private Logger logger = LoggerFactory.getLogger(getClass());

	private static final List<Todo> Todos_List = List.of(new Todo("dom", "Learn aws"),
			new Todo("dom", "Learn ng"));

	@GetMapping("/todos")
	public List<Todo> retrieveAllTodos() {
		return Todos_List;
	}

	@GetMapping("/users/{username}/todos")
	@PreAuthorize("hasRole('USER') and #username == authentication.name")
	@PostAuthorize("returnObject.username == 'dom'")
	@RolesAllowed({"ADMIN", "USER"})
	@Secured({"ROLE_ADMIN", "ROLE_USER"})
	public Todo retrieveTodosForASpecificUser(@PathVariable String username) {
		return Todos_List.get(0);
	}
	
	@PostMapping("/users/{username}/todos")
	public void createTodosForASpecificUser(@PathVariable String username, @RequestBody Todo todo) {
		logger.info("create {} for {}", todo, username);
	}
}

record Todo(String username, String description) {
}

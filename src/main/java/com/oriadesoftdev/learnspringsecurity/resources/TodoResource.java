package com.oriadesoftdev.learnspringsecurity.resources;

import jakarta.annotation.security.RolesAllowed;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class TodoResource {

    private static final List<Todo> TODOS_LIST = List.of(
            new Todo("Oriade", "Learn AWS"),
            new Todo("Oriade", "Learn Cloud DevOps"),
            new Todo("Oriade", "Learn Android Development")
    );

    @GetMapping("/todos")
    public List<Todo> retrieveTodos() {
        return TODOS_LIST;
    }

    @GetMapping("/users/{username}/todos")
    @PreAuthorize("hasRole('USER') and #username == authentication.name")
    @PostAuthorize("returnObject.username == 'Oriade'")
    @RolesAllowed({"USER", "ADMIN"})
    @Secured({"ROLE_USER", "ROLE_ADMIN"})
    public Todo retrieveTodosForSpecificUser(@PathVariable String username) {
        return TODOS_LIST.get(0);
    }

    @PostMapping("/users/{username}/todos")
    public void createTodoForSpecificUser(@PathVariable String username, @RequestBody Todo todo) {
//        TODOS_LIST.add(todo);
    }

    record Todo(String username, String description) {
    }
}

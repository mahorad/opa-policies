#Added  a new role named "user" that can only do a select clause on the request. And added a new method POST for admin. 
package httpapi.authz

default allow = false

role_permissions = {
	"admin": {"*": {"*": ["*"]}},
	"guest": {"Authors": {
		"totalSoldCopies": ["$select"],
		"ID": ["$select"],
	}},
	"librarian": {"Books": {
		"title": ["$select"],
		"price": ["$select"],
		"*": ["$expand"],
	}},
    "customer": {
		"Books": {"*": ["$expand", "$select"]},
		"Authors": {"*": ["$select"]},
	},
	"author": {
		"Books": {"*": ["$expand", "$select"]},
		"Authors": {"*": ["$select"]},
	},
}

# Policy to handle GET requests
allow {
	input.method == "GET"
	input.path = ["", "odata", "v4", "book", entity]
	role := input.user.role
	has_entity_permission(role, entity)
	count(input.query) > 0
	not query_violates_permissions(role, entity)
}

# Policy to handle POST for "Books" Entity
allow {
	input.method == "POST"
	input.path = ["", "odata", "v4", "book", "Books"]
	input.user.role == "admin"
}

# Policy to handle POST for "Authors" entity
allow {
	input.method == "POST"
	input.path = ["", "odata", "v4", "book", "Authors"]
	input.user.role == "admin"
}

# Returns true if the entity violates the permissions
entity_violates_permissions(role, entity) {
	not has_entity_permission(role, entity)
}

# Returns true if any part of the query violates the permissions
query_violates_permissions(role, entity) {
	operations := ["$filter", "$select", "$expand", "$orderby", "$top", "$skip", "$count", "$search", "$format"]

	operation := operations[_]
	properties := split(input.query[operation], ",")
	property := properties[_]
	not has_operation_permission(role, entity, operation, property)
}

# Checks if a role has a specific permission
has_operation_permission(role, entity, operation, property) {
	role_permissions[role][entity][property][_] == operation
}

has_operation_permission(role, _, _, _) {
	role_permissions[role]["*"]["*"][_] == "*"
}

has_operation_permission(role, entity, operation, _) {
	role_permissions[role][entity]["*"][_] == operation
}

has_operation_permission(role, _, operation, _) {
	role_permissions[role]["*"]["*"][_] == operation
}

# Checks if a role has permission to access an entity
has_entity_permission(role, entity) {
	role_permissions[role][entity]
}

has_entity_permission(role, _) {
	role_permissions[role]["*"]
}
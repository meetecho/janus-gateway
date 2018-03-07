/*! \file    config.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Configuration files parsing
 * \details  Implementation of a parser of INI and YAML configuration files.
 * 
 * \ingroup core
 * \ref core
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <libgen.h>

#include <yaml.h>

#include "config.h"
#include "debug.h"
#include "utils.h"


/* Filename helper */
static char *get_filename(char *path) {
	return basename(path);
}

static gboolean is_yaml_config(const char *path) {
	if(path == NULL)
		return FALSE;
	return strstr(path, ".yaml") != NULL;
}

/* Trimming helper */
static char *ltrim(char *s) {
	if(strlen(s) == 0)
		return s;
	while(isspace(*s))
		s++;
	return s;
}

static char *rtrim(char *s) {
	if(strlen(s) == 0)
		return s;
	char *back = s + strlen(s);
	while(isspace(*--back));
	*(back+1) = '\0';
	return s;
}

static char *trim(char *s) {
	if(strlen(s) == 0)
		return s;
	return rtrim(ltrim(s)); 
}


/* Helper to debug Yaml parsing and events */
#define EVENT_STR(name) case name: return #name
static const char *janus_config_yaml_event(yaml_event_type_t type) {
	switch(type) {
		EVENT_STR(YAML_NO_EVENT);
		EVENT_STR(YAML_STREAM_START_EVENT);
		EVENT_STR(YAML_STREAM_END_EVENT);
		EVENT_STR(YAML_DOCUMENT_START_EVENT);
		EVENT_STR(YAML_DOCUMENT_END_EVENT);
		EVENT_STR(YAML_MAPPING_START_EVENT);
		EVENT_STR(YAML_SEQUENCE_START_EVENT);
		EVENT_STR(YAML_MAPPING_END_EVENT);
		EVENT_STR(YAML_SEQUENCE_END_EVENT);
		EVENT_STR(YAML_ALIAS_EVENT);
		EVENT_STR(YAML_SCALAR_EVENT);
		default:
			break;
	}
	return NULL;
}

/* Parse a configuration file */
janus_config *janus_config_parse(const char *config_file) {
	if(config_file == NULL)
		return NULL;
	char *tmp_filename = g_strdup(config_file);
	char *filename = get_filename(tmp_filename);
	if(filename == NULL) {
		g_free(tmp_filename);
		JANUS_LOG(LOG_ERR, "Invalid filename %s\n", config_file);
		return NULL;
	}
	/* Open file */
	FILE *file = fopen(config_file, "rt");
	if(!file) {
		g_free(tmp_filename);
		JANUS_LOG(LOG_ERR, "  -- Error reading configuration file '%s'... error %d (%s)\n", filename, errno, strerror(errno));
		return NULL;
	}
	/* Create configuration instance */
	janus_config *jc = g_malloc0(sizeof(janus_config));
	jc->name = g_strdup(filename);
	/* Is this a YAML or INI config file? */
	jc->is_yaml = is_yaml_config(jc->name);
	if(jc->is_yaml) {
		/* Parse with libyaml and not manually */
		yaml_parser_t parser;
		if(!yaml_parser_initialize(&parser)) {
			JANUS_LOG(LOG_ERR, "Error initializing YAML parser\n");
			goto error;
		}
		yaml_parser_set_input_file(&parser, file);
		/* Traverse the document */
		gboolean error = FALSE;
		yaml_event_t event;
		int depth = 0;
		GList *cats = NULL, *last = NULL;
		janus_config_container *cg = NULL, *pc = NULL;
		char *name = NULL, *value = NULL;
		while(!error) {
			if(!yaml_parser_parse(&parser, &event)) {
				JANUS_LOG(LOG_ERR, "Parser error: %s\n", parser.problem);
				error = TRUE;
				break;
			}
			JANUS_LOG(LOG_HUGE, "%s\n", janus_config_yaml_event(event.type));
			switch(event.type) {
				case YAML_NO_EVENT:
					JANUS_LOG(LOG_WARN, "No event!\n");
					break;
				/* Stream start/end */
				case YAML_STREAM_START_EVENT:
					break;
				case YAML_STREAM_END_EVENT:
					break;
				/* Block delimeters */
				case YAML_DOCUMENT_START_EVENT:
					break;
				case YAML_DOCUMENT_END_EVENT:
					break;
				case YAML_MAPPING_START_EVENT:
				case YAML_SEQUENCE_START_EVENT:
					depth++;
					/* Create category or array */
					if(name != NULL) {
						if(depth == 2) {
							/* Main category or array */
							if(event.type == YAML_MAPPING_START_EVENT)
								cg = janus_config_category_create(name);
							else
								cg = janus_config_array_create(name);
							janus_config_add(jc, NULL, cg);
							cats = g_list_append(cats, cg);
						} else {
							/* Subcategory/subarray */
							pc = cg;
							if(event.type == YAML_MAPPING_START_EVENT)
								cg = janus_config_category_create(name);
							else
								cg = janus_config_array_create(name);
							janus_config_add(jc, pc, cg);
							cats = g_list_append(cats, cg);
						}
						if(cg == NULL) {
							JANUS_LOG(LOG_ERR, "Error adding %s %s (%s)\n",
								event.type == YAML_MAPPING_START_EVENT ? "category" : "array",
								event.data.scalar.value, filename);
							error = TRUE;
							break;
						}
						g_free(name);
						name = NULL;
					}
					break;
				case YAML_MAPPING_END_EVENT:
				case YAML_SEQUENCE_END_EVENT:
					depth--;
					g_free(name);
					name = NULL;
					last = g_list_last(cats);
					if(last)
						cats = g_list_remove(cats, last->data);
					if(depth == 1) {
						cg = NULL;
					} else {
						last = g_list_last(cats);
						cg = (janus_config_category *)(last ? last->data : NULL);
					}
					break;
				/* Data */
				case YAML_ALIAS_EVENT:
					/* TODO: should we support these? */
					break;
				case YAML_SCALAR_EVENT:
					/* If this is the name of the category/array, just take note of the name */
					value = (char *)event.data.scalar.value;
					if(value == NULL || strlen(value) == 0 || !strcmp(value, "null")) {
						if(name && (!cg || (cg && cg->type != janus_config_type_array))) {
							/* Can it be an empty category? */
							pc = janus_config_category_create(name);
							if(janus_config_add(jc, cg, pc) < 0) {
								JANUS_LOG(LOG_ERR, "Error adding empty category %s (%s)\n", name, filename);
								error = TRUE;
								break;
							}
							g_free(name);
							name = NULL;
							break;
						}
					}
					if(name != NULL) {
						janus_config_item *item = janus_config_item_create(name, value);
						if(janus_config_add(jc, cg, item) < 0) {
							janus_config_container_destroy(item);
							JANUS_LOG(LOG_ERR, "Error adding item %s (%s)\n", name, filename);
							error = TRUE;
							break;
						}
						g_free(name);
						name = NULL;
					} else {
						if(cg != NULL && cg->type == janus_config_type_array) {
							/* Item with no value, just name */
							janus_config_item *item = janus_config_item_create(value, NULL);
							if(janus_config_add(jc, cg, item) < 0) {
								janus_config_container_destroy(item);
								JANUS_LOG(LOG_ERR, "Error adding value-less item %s (%s)\n", value, filename);
								error = TRUE;
								break;
							}
						} else {
							/* Take note of the name, we'll need it later */
							name = g_strdup(value);
						}
					}
					break;
				default:
					JANUS_LOG(LOG_WARN, "??\n");
					break;
			}
			if(event.type == YAML_STREAM_END_EVENT)
				break;
			yaml_event_delete(&event);
		}
		g_free(name);
		yaml_event_delete(&event);
		yaml_parser_delete(&parser);
		if(error)
			goto error;
		/* We're done */
		goto done;
	}
	/* Not YAML: assume INI, traverse manually and parse it */
	int line_number = 0;
	char line_buffer[BUFSIZ];
	janus_config_category *cg = NULL;
	while(fgets(line_buffer, sizeof(line_buffer), file)) {
		line_number++;
		if(strlen(line_buffer) == 0)
			continue;
		/* Strip comments */
		char *line = line_buffer, *sc = line, *c = NULL;
		while((c = strchr(sc, ';')) != NULL) {
			if(c == line || *(c-1) != '\\') {
				/* Comment starts here */
				*c = '\0';
				break;
			}
			/* Escaped semicolon, remove the slash */
			sc = c-1;
			/* length will be at least 2: ';' '\0' */
			memmove(sc, c, strlen(c)+1);
			/* Go on */
			sc++;
		}
		/* Trim (will remove newline characters too) */
		line = trim(line);
		if(strlen(line) == 0)
			continue;
		/* Parse */
		if(line[0] == '[') {
			/* Category */
			line++;
			char *end = strchr(line, ']');
			if(end == NULL) {
				JANUS_LOG(LOG_ERR, "Error parsing category at line %d: syntax error (%s)\n", line_number, filename);
				goto error;
			}
			*end = '\0';
			line = trim(line);
			if(strlen(line) == 0) {
				JANUS_LOG(LOG_ERR, "Error parsing category at line %d: no name (%s)\n", line_number, filename);
				goto error;
			}
			cg = janus_config_category_create(line);
			if(janus_config_add(jc, NULL, cg) < 0) {
				janus_config_container_destroy(cg);
				JANUS_LOG(LOG_ERR, "Error adding category %s (%s)\n", line, filename);
				goto error;
			}
		} else {
			/* Item */
			char *name = line, *value = strchr(line, '=');
			if(value == NULL || value == line) {
				JANUS_LOG(LOG_ERR, "Error parsing item at line %d (%s)\n", line_number, filename);
				goto error;
			}
			*value = '\0';
			name = trim(name);
			if(strlen(name) == 0) {
				JANUS_LOG(LOG_ERR, "Error parsing item at line %d: no name (%s)\n", line_number, filename);
				goto error;
			}
			value++;
			value = trim(value);
			if(strlen(value) > 0) {
				if(*value == '>') {
					value++;
					value = trim(value);
					if(strlen(value) == 0) {
						JANUS_LOG(LOG_ERR, "Error parsing item at line %d: no value (%s)\n", line_number, filename);
						goto error;
					}
				}
			}
			janus_config_item *item = janus_config_item_create(name, value);
			if(janus_config_add(jc, cg, item) < 0) {
				janus_config_container_destroy(item);
				if(cg == NULL)
					JANUS_LOG(LOG_ERR, "Error adding item %s (%s)\n", name, filename);
				else
					JANUS_LOG(LOG_ERR, "Error adding item %s to category %s (%s)\n", name, cg->name, filename);
				goto error;
			}
		}
	}
done:
	g_free(tmp_filename);
	fclose(file);
	return jc;

error:
	g_free(tmp_filename);
	fclose(file);
	janus_config_destroy(jc);
	return NULL;
}

janus_config *janus_config_create(const char *name) {
	if(name == NULL)
		return NULL;
	janus_config *jc = g_malloc0(sizeof(janus_config));
	jc->name = g_strdup(name);
	/* Is this a YAML or INI config file? */
	jc->is_yaml = is_yaml_config(jc->name);
	return jc;
}


/* Containers management */
janus_config_item *janus_config_item_create(const char *name, const char *value) {
	if(name == NULL)
		return NULL;
	janus_config_item *item = g_malloc0(sizeof(janus_config_item));
	item->type = janus_config_type_item;
	item->name = g_strdup(name);
	if(value)
		item->value = g_strdup(value);
	return item;
}

janus_config_category *janus_config_category_create(const char *name) {
	if(name == NULL)
		return NULL;
	janus_config_category *category = g_malloc0(sizeof(janus_config_category));
	category->type = janus_config_type_category;
	category->name = g_strdup(name);
	return category;
}

janus_config_array *janus_config_array_create(const char *name) {
	if(name == NULL)
		return NULL;
	janus_config_array *array = g_malloc0(sizeof(janus_config_array));
	array->type = janus_config_type_array;
	array->name = g_strdup(name);
	return array;
}

void janus_config_container_destroy(janus_config_container *container) {
	if(container) {
		if(container->name)
			g_free((gpointer)container->name);
		if(container->value)
			g_free((gpointer)container->value);
		if(container->list)
			g_list_free_full(container->list, (GDestroyNotify)janus_config_container_destroy);
		g_free(container);
	}
}

static janus_config_container *janus_config_get_internal(janus_config *config,
		janus_config_container *parent, janus_config_type type, const char *name, gboolean create) {
	if(config == NULL || name == NULL)
		return NULL;
	if(parent != NULL && parent->type != janus_config_type_category && parent->type != janus_config_type_array)
		return NULL;
	janus_config_container *c = NULL;
	GList *l = parent ? parent->list : config->list;
	while(l) {
		c = (janus_config_container *)l->data;
		if(c && c->name && !strcasecmp(name, c->name) &&
				(type == janus_config_type_any || c->type == type))
			return c;
		l = l->next;
	}
	/* If we got here, it doesn't exist, should we create it? */
	c = NULL;
	if(create) {
		if(type == janus_config_type_category) {
			c = janus_config_category_create(name);
		} else if(type == janus_config_type_category) {
			c = janus_config_array_create(name);
		} else {
			JANUS_LOG(LOG_WARN, "Not a category and not an array, not creating anything...\n");
		}
		if(c != NULL)
			janus_config_add(config, parent, c);
	}
	return c;
}

janus_config_container *janus_config_get(janus_config *config,
		janus_config_container *parent, janus_config_type type, const char *name) {
	return janus_config_get_internal(config, parent, type, name, FALSE);
}

janus_config_container *janus_config_get_create(janus_config *config,
		janus_config_container *parent, janus_config_type type, const char *name) {
	return janus_config_get_internal(config, parent, type, name, TRUE);
}

janus_config_container *janus_config_search(janus_config *config, ...) {
	if(config == NULL)
		return NULL;
	va_list args;
	va_start(args, config);
	char *name = va_arg(args, char *);
	if(name == NULL) {
		va_end(args);
		return NULL;
	}
	/* Get the full path we're looking for */
	GList *path = NULL;
	while(name) {
		path = g_list_append(path, name);
		name = va_arg(args, char *);
	}
	va_end(args);
	/* Start looking */
	janus_config_container *parent = NULL, *c = NULL;
	while(path) {
		name = (char *)path->data;
		c = janus_config_get(config, parent, janus_config_type_any, name);
		if(c == NULL) {
			/* Not found */
			break;
		}
		parent = c;
		/* Next parent */
		path = path->next;
	}
	return c;
}

int janus_config_add(janus_config *config, janus_config_container *container, janus_config_container *item) {
	if(config == NULL || item == NULL)
		return -1;
	if(container != NULL && container->type != janus_config_type_category && container->type != janus_config_type_array)
		return -2;
	if(container) {
		/* Add to parent */
		container->list = g_list_append(container->list, item);
	} else {
		/* Add to root */
		config->list = g_list_append(config->list, item);
	}
	return 0;
}

int janus_config_remove(janus_config *config, janus_config_container *container, const char *name) {
	if(config == NULL || name == NULL)
		return -1;
	if(container != NULL && container->type != janus_config_type_category && container->type != janus_config_type_array)
		return -2;
	janus_config_container *item = janus_config_get(config, container, janus_config_type_any, name);
	if(item == NULL)
		return -3;
	if(container) {
		/* Remove from parent */
		container->list = g_list_remove(container->list, item);
	} else {
		/* Remove from root */
		config->list = g_list_remove(config->list, item);
	}
	janus_config_container_destroy(item);
	return 0;
}

GList *janus_config_get_items(janus_config *config, janus_config_container *parent) {
	if(config == NULL || (parent != NULL && parent->type != janus_config_type_category
			&& parent->type != janus_config_type_array))
		return NULL;
	GList *list = NULL, *clist = parent ? parent->list : config->list;
	while(clist) {
		janus_config_container *c = (janus_config_container *)clist->data;
		if(c && c->type == janus_config_type_item)
			list = g_list_append(list, c);
		clist = clist->next;
	}
	return list;
}

GList *janus_config_get_categories(janus_config *config, janus_config_container *parent) {
	if(config == NULL || (parent != NULL && parent->type != janus_config_type_category
			&& parent->type != janus_config_type_array))
		return NULL;
	GList *list = NULL, *clist = parent ? parent->list : config->list;
	while(clist) {
		janus_config_container *c = (janus_config_container *)clist->data;
		if(c && c->type == janus_config_type_category)
			list = g_list_append(list, c);
		clist = clist->next;
	}
	return list;
}

GList *janus_config_get_arrays(janus_config *config, janus_config_container *parent) {
	if(config == NULL || (parent != NULL && parent->type != janus_config_type_category
			&& parent->type != janus_config_type_array))
		return NULL;
	GList *list = NULL, *clist = parent ? parent->list : config->list;
	while(clist) {
		janus_config_container *c = (janus_config_container *)clist->data;
		if(c && c->type == janus_config_type_array)
			list = g_list_append(list, c);
		clist = clist->next;
	}
	return list;
}


/* Printing utilities */
void janus_config_print(janus_config *config) {
	janus_config_print_as(config, LOG_VERB);
}

#define JANUS_CONFIG_INDENT 4
static void janus_config_print_list(int level, GList *l, int indent) {
	while(l) {
		janus_config_container *c = (janus_config_container *)l->data;
		if(c->type == janus_config_type_item) {
			JANUS_LOG(level, "%*s%s: %s\n", indent, "",
				c->name ? c->name : "(none)", c->value ? c->value : "(none)");
		} else if(c->type == janus_config_type_category) {
			JANUS_LOG(level, "%*s%s: {\n", indent, "",
				c->name ? c->name : "(none)");
			if(c->list)
				janus_config_print_list(level, c->list, indent+JANUS_CONFIG_INDENT);
			JANUS_LOG(level, "%*s}\n", indent, "");
		} else if(c->type == janus_config_type_array) {
			JANUS_LOG(level, "%*s%s: [\n", indent, "",
				c->name ? c->name : "(none)");
			if(c->list)
				janus_config_print_list(level, c->list, indent+JANUS_CONFIG_INDENT);
			JANUS_LOG(level, "%*s]\n", indent, "");
		}
		l = l->next;
	}
}

void janus_config_print_as(janus_config *config, int level) {
	if(config == NULL)
		return;
	JANUS_LOG(level, "[%s]\n", config->name ? config->name : "??");
	if(config->list)
		janus_config_print_list(level, config->list, JANUS_CONFIG_INDENT);
}

static void janus_config_save_list(janus_config *config, FILE *file, int level, gboolean array, GList *list, yaml_emitter_t *emitter) {
	if(config == NULL || file == NULL || list == NULL )
		return;
	GList *l = list;
	yaml_event_t output_event;
	while(l) {
		janus_config_container *c = (janus_config_container *)l->data;
		if(c->name == NULL) {
			l = l->next;
			continue;
		}
		if(c->type == janus_config_type_item) {
			if(config->is_yaml) {
				yaml_scalar_event_initialize(&output_event,
					NULL, (yaml_char_t *)YAML_STR_TAG, (yaml_char_t *)c->name,
					-1, 1, 1, YAML_PLAIN_SCALAR_STYLE);
				yaml_emitter_emit(emitter, &output_event);
				if(!array) {
					yaml_scalar_event_initialize(&output_event,
						NULL, (yaml_char_t *)YAML_STR_TAG, (yaml_char_t *)(c->value ? c->value : ""),
						-1, 1, 1, YAML_PLAIN_SCALAR_STYLE);
					yaml_emitter_emit(emitter, &output_event);
				}
			} else {
				fwrite(c->name, sizeof(char), strlen(c->name), file);
				fwrite(" = ", sizeof(char), 3, file);
				/* If the value contains a semicolon, escape it */
				if(strchr(c->value, ';')) {
					char *value = g_strdup(c->value);
					value = janus_string_replace((char *)value, ";", "\\;");
					fwrite(value, sizeof(char), strlen(value), file);
					fwrite("\n", sizeof(char), 1, file);
					g_free(value);
				} else {
					/* No need to escape */
					fwrite(c->value, sizeof(char), strlen(c->value), file);
					fwrite("\n", sizeof(char), 1, file);
				}
			}
		} else if(c->type == janus_config_type_category) {
			if(config->is_yaml) {
				yaml_scalar_event_initialize(&output_event,
					NULL, (yaml_char_t *)YAML_STR_TAG, (yaml_char_t *)c->name,
					-1, 1, 1, YAML_PLAIN_SCALAR_STYLE);
				yaml_emitter_emit(emitter, &output_event);
			} else {
				if(level > 0) {
					/* INI files don't support indented categories */
					JANUS_LOG(LOG_WARN, "Dropping indented category %s (unsupported in INI files)\n", c->name);
				} else {
					fwrite("[", sizeof(char), 1, file);
					fwrite(c->name, sizeof(char), strlen(c->name), file);
					fwrite("]\n", sizeof(char), 2, file);
				}
			}
			if(c->list == NULL) {
				/* Empty category */
				if(config->is_yaml) {
					yaml_scalar_event_initialize(&output_event,
						NULL, (yaml_char_t *)YAML_STR_TAG, (yaml_char_t *)"",
						-1, 1, 1, YAML_PLAIN_SCALAR_STYLE);
					yaml_emitter_emit(emitter, &output_event);
				}
			} else {
				/* Non-empty category */
				if(config->is_yaml) {
					yaml_mapping_start_event_initialize(&output_event,
						NULL, (yaml_char_t *)YAML_MAP_TAG, 1,
						YAML_ANY_MAPPING_STYLE);
					yaml_emitter_emit(emitter, &output_event);
				}
				janus_config_save_list(config, file, level+1, FALSE, c->list, emitter);
				/* Done */
				if(config->is_yaml) {
					yaml_mapping_end_event_initialize(&output_event);
					yaml_emitter_emit(emitter, &output_event);
				}
			}
			if(!config->is_yaml)
				fwrite("\r\n", sizeof(char), 2, file);
		} else if(c->type == janus_config_type_array) {
			if(!config->is_yaml) {
				/* INI files don't support arrays */
				JANUS_LOG(LOG_WARN, "Dropping array %s (unsupported in INI files)\n", c->name);
			} else {
				yaml_scalar_event_initialize(&output_event,
					NULL, (yaml_char_t *)YAML_STR_TAG, (yaml_char_t *)c->name,
					-1, 1, 1, YAML_PLAIN_SCALAR_STYLE);
				yaml_emitter_emit(emitter, &output_event);
				if(c->list == NULL) {
					/* Empty array (will turn into a category though) */
					yaml_scalar_event_initialize(&output_event,
						NULL, (yaml_char_t *)YAML_STR_TAG, (yaml_char_t *)"",
						-1, 1, 1, YAML_PLAIN_SCALAR_STYLE);
					yaml_emitter_emit(emitter, &output_event);
				} else {
					/* Non-empty array */
					yaml_sequence_start_event_initialize(&output_event,
						NULL, (yaml_char_t *)YAML_SEQ_TAG, 1,
						YAML_ANY_SEQUENCE_STYLE);
					yaml_emitter_emit(emitter, &output_event);
					janus_config_save_list(config, file, level+1, TRUE, c->list, emitter);
					/* Done */
					yaml_sequence_end_event_initialize(&output_event);
					yaml_emitter_emit(emitter, &output_event);
				}
			}
		}
		l = l->next;
	}
}

gboolean janus_config_save(janus_config *config, const char *folder, const char *filename) {
	if(config == NULL)
		return -1;
	/* If this is a YAML configuration, create an emitter */
	yaml_emitter_t emitter;
	yaml_event_t output_event;
    if(config->is_yaml && !yaml_emitter_initialize(&emitter)) {
        JANUS_LOG(LOG_ERR, "Could not inialize the YAML emitter object\n");
        return -1;
    }
	/* Open the file */
	FILE *file = NULL;
	char path[1024];
	if(folder != NULL) {
		/* Create folder, if needed */
		if(janus_mkdir(folder, 0755) < 0) {
			JANUS_LOG(LOG_ERR, "Couldn't save configuration file, error creating folder '%s'...\n", folder);
			if(config->is_yaml)
				yaml_emitter_delete(&emitter);
			return -2;
		}
		g_snprintf(path, 1024, "%s/%s.%s", folder, filename, config->is_yaml ? "yaml" : "cfg");
	} else {
		g_snprintf(path, 1024, "%s.%s", filename, config->is_yaml ? "yaml" : "cfg");
	}
	file = fopen(path, "wt");
	if(file == NULL) {
		JANUS_LOG(LOG_ERR, "Couldn't save configuration file, error opening file '%s'...\n", path);
		if(config->is_yaml)
			yaml_emitter_delete(&emitter);
		return -3;
	}
	/* Print a header/comment */
	char date[64], header[256];
	struct tm tmresult;
	time_t ltime = time(NULL);
	localtime_r(&ltime, &tmresult);
	strftime(date, sizeof(date), "%a %b %e %T %Y", &tmresult);
	char comment = config->is_yaml ? '#' : ';';
	g_snprintf(header, 256, "%c\n%c File automatically generated on %s\n%c\n\n",
		comment, comment, date, comment);
	fwrite(header, sizeof(char), strlen(header), file);
	/* If this is a YAML output file, do some preparations */
	if(config->is_yaml) {
		yaml_emitter_set_output_file(&emitter, file);
		yaml_stream_start_event_initialize(&output_event, YAML_UTF8_ENCODING);
		yaml_emitter_emit(&emitter, &output_event);
		yaml_document_start_event_initialize(&output_event, NULL, NULL, NULL, 0);
		yaml_emitter_emit(&emitter, &output_event);
		yaml_mapping_start_event_initialize(&output_event,
			NULL, (yaml_char_t *)YAML_MAP_TAG, 1,
			YAML_ANY_MAPPING_STYLE);
		yaml_emitter_emit(&emitter, &output_event);
	}
	/* Go on with the configuration */
	if(config->list)
		janus_config_save_list(config, file, 0, FALSE, config->list, &emitter);
	/* If this is a YAML output file, close up */
	if(config->is_yaml) {
		yaml_mapping_end_event_initialize(&output_event);
		yaml_emitter_emit(&emitter, &output_event);
		yaml_document_end_event_initialize(&output_event, 0);
		yaml_emitter_emit(&emitter, &output_event);
		yaml_stream_end_event_initialize(&output_event);
		yaml_emitter_emit(&emitter, &output_event);
		yaml_event_delete(&output_event);
		yaml_emitter_delete(&emitter);
	}
	/* Done */
	fclose(file);
	return 0;
}

void janus_config_destroy(janus_config *config) {
	if(config == NULL)
		return;
	if(config->list) {
		g_list_free_full(config->list, (GDestroyNotify)janus_config_container_destroy);
		config->list = NULL;
	}
	if(config->name)
		g_free((gpointer)config->name);
	g_free((gpointer)config);
	config = NULL;
}

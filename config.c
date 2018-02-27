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


/* Memory management helpers */
static void janus_config_free_item(gpointer data) {
	janus_config_item *i = (janus_config_item *)data;
	if(i) {
		if(i->name)
			g_free((gpointer)i->name);
		if(i->value)
			g_free((gpointer)i->value);
		if(i->items)
			g_list_free_full(i->items, janus_config_free_item);
		if(i->subcategories)
			g_list_free_full(i->subcategories, janus_config_free_item);
		g_free(i);
	}
}

static void janus_config_free_category(gpointer data) {
	janus_config_free_item(data);
}


/* Public methods */
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
		yaml_event_t event;
		gboolean error = FALSE;
		int depth = 0;
		janus_config_category *cg = NULL;
		char *name = NULL, *value = NULL;
		while(!error) {
			if(!yaml_parser_parse(&parser, &event)) {
				error = TRUE;
				break;
			}
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
				case YAML_SEQUENCE_START_EVENT:
					/* TODO: we need to support sequences */
					break;
				case YAML_SEQUENCE_END_EVENT:
					/* TODO: we need to support sequences */
					break;
				case YAML_MAPPING_START_EVENT:
					depth++;
					if(depth == 2) {
						/* Create category */
						if(name != NULL) {
							cg = janus_config_add_category(jc, name);
							if(cg == NULL) {
								JANUS_LOG(LOG_ERR, "Error adding category %s (%s)\n", event.data.scalar.value, filename);
								error = TRUE;
								break;
							}
							g_free(name);
							name = NULL;
						}
					}
					/* TODO: add support for more innested categories and items */
					break;
				case YAML_MAPPING_END_EVENT:
					depth--;
					g_free(name);
					name = NULL;
					cg = NULL;
					break;
				/* Data */
				case YAML_ALIAS_EVENT:
					/* TODO: should we support these? */
					break;
				case YAML_SCALAR_EVENT:
					/* depth=1 is a category or category level attribute, depth=2 is an attribute
					 * TODO: support more innested stuff for the future (API-wise too) */
					value = (char *)event.data.scalar.value;
					if(depth == 1) {
						/* New category or category-level attribute? */
						if(value == NULL || strlen(value) == 0 || !strcmp(value, "null")) {
							/* Create empty category */
							if(name != NULL) {
								cg = janus_config_add_category(jc, name);
								if(cg == NULL) {
									JANUS_LOG(LOG_ERR, "Error adding category %s (%s)\n", value, filename);
									error = TRUE;
									break;
								}
								g_free(name);
								name = NULL;
								cg = NULL;
							}
							break;
						}
						if(name != NULL) {
							if(value != NULL && strlen(value) > 0) {
								if(janus_config_add_item(jc, NULL, name, value) == NULL) {
									JANUS_LOG(LOG_ERR, "Error adding item %s (%s)\n", name, filename);
									error = TRUE;
									break;
								}
							}
						} else if(value != NULL && strlen(value) > 0) {
							name = g_strdup(value);
						}
					} else if(depth == 2) {
						if(value == NULL || strlen(value) == 0) {
							/* Drop attribute without value */
							JANUS_LOG(LOG_WARN, "Dropping value-less attribute %s (%s)\n", name, filename);
							g_free(name);
							name = NULL;
							break;
						}
						if(name == NULL) {
							/* Take note of the attribute name */
							name = g_strdup(value);
						} else if(name != NULL) {
							/* Add new item to the current category */
							if(janus_config_add_item(jc, cg->name, name, value) == NULL) {
								JANUS_LOG(LOG_ERR, "Error adding item %s to category %s (%s)\n", name, cg->name, filename);
								error = TRUE;
								break;
							}
							g_free(name);
							name = NULL;
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
		yaml_parser_delete(&parser);
		if(error) {
			JANUS_LOG(LOG_ERR, "Error parsing YAML configuration file (%s)\n", filename);
			goto error;
		}
		yaml_event_delete(&event);
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
			cg = janus_config_add_category(jc, line);
			if(cg == NULL) {
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
			if(strlen(value) == 0) {
				JANUS_LOG(LOG_ERR, "Error parsing item at line %d: no value (%s)\n", line_number, filename);
				goto error;
			}
			if(*value == '>') {
				value++;
				value = trim(value);
				if(strlen(value) == 0) {
					JANUS_LOG(LOG_ERR, "Error parsing item at line %d: no value (%s)\n", line_number, filename);
					goto error;
				}
			}
			if(janus_config_add_item(jc, cg ? cg->name : NULL, name, value) == NULL) {
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

GList *janus_config_get_categories(janus_config *config) {
	if(config == NULL)
		return NULL;
	return config->categories;
}

janus_config_category *janus_config_get_category(janus_config *config, const char *name) {
	if(config == NULL || name == NULL)
		return NULL;
	if(config->categories == NULL)
		return NULL;
	GList *l = config->categories;
	while(l) {
		janus_config_category *c = (janus_config_category *)l->data;
		if(c && c->category && c->name && !strcasecmp(name, c->name))
			return c;
		l = l->next;
	}
	return NULL;
}

GList *janus_config_get_items(janus_config_category *category) {
	if(category == NULL)
		return NULL;
	return category->items;
}

janus_config_item *janus_config_get_item(janus_config_category *category, const char *name) {
	if(category == NULL || name == NULL)
		return NULL;
	if(category->items == NULL)
		return NULL;
	GList *l = category->items;
	while(l) {
		janus_config_item *i = (janus_config_item *)l->data;
		if(i && i->name && !strcasecmp(name, i->name))
			return i;
		l = l->next;
	}
	return NULL;
}

janus_config_item *janus_config_get_item_drilldown(janus_config *config, const char *category, const char *name) {
	if(config == NULL || category == NULL || name == NULL)
		return NULL;
	janus_config_category *c = janus_config_get_category(config, category);
	if(c == NULL)
		return NULL;
	return janus_config_get_item(c, name);
}

janus_config_category *janus_config_add_category(janus_config *config, const char *category) {
	if(config == NULL || category == NULL)
		return NULL;
	janus_config_category *c = janus_config_get_category(config, category);
	if(c != NULL) {
		/* Category exists, return this */
		return c;
	}
	c = g_malloc0(sizeof(janus_config_category));
	c->category = TRUE;
	c->name = g_strdup(category);
	config->categories = g_list_append(config->categories, c);
	return c;
}

int janus_config_remove_category(janus_config *config, const char *category) {
	if(config == NULL || category == NULL)
		return -1;
	janus_config_category *c = janus_config_get_category(config, category);
	if(c) {
		config->categories = g_list_remove(config->categories, c);
		janus_config_free_category(c);
		return 0;
	}
	return -2;
}

janus_config_item *janus_config_add_item(janus_config *config, const char *category, const char *name, const char *value) {
	if(config == NULL || name == NULL || value == NULL)
		return NULL;
	/* This will return the existing category, if it exists already */
	janus_config_category *c = category ? janus_config_add_category(config, category) : NULL;
	if(category != NULL && c == NULL) {
		/* Create it */
		JANUS_LOG(LOG_FATAL, "Category error!\n");
		return NULL;
	}
	janus_config_item *item = c ? janus_config_get_item(c, name) : NULL;
	if(item == NULL) {
		/* Create it */
		item = g_malloc0(sizeof(janus_config_item));
		item->category = FALSE;
		item->name = g_strdup(name);
		item->value = g_strdup(value);
		if(c != NULL) {
			/* Add to category */
			c->items = g_list_append(c->items, item);
		} else {
			/* Uncategorized item */
			config->items = g_list_append(config->items, item);
		}
	} else {
		/* Update it */
		char *item_value = g_strdup(value);
		if(item->value)
			g_free((gpointer)item->value);
		item->value = item_value;
	}
	return item;
}

int janus_config_remove_item(janus_config *config, const char *category, const char *name) {
	if(config == NULL || category == NULL || name == NULL)
		return -1;
	janus_config_category *c = janus_config_add_category(config, category);
	if(c == NULL)
		return -2;
	janus_config_item *item = janus_config_get_item(c, name);
	if(item == NULL)
		return -3;
	c->items = g_list_remove(c->items, item);
	janus_config_free_item(item);
	return 0;
}

void janus_config_print(janus_config *config) {
	if(config == NULL)
		return;
	JANUS_LOG(LOG_VERB, "[%s]\n", config->name ? config->name : "??");
	if(config->items) {
		GList *l = config->items;
		while(l) {
			janus_config_item *i = (janus_config_item *)l->data;
			JANUS_LOG(LOG_VERB, "        %s: %s\n", i->name ? i->name : "??", i->value ? i->value : "??");
			l = l->next;
		}
	}
	if(config->categories) {
		GList *l = config->categories;
		while(l) {
			janus_config_category *c = (janus_config_category *)l->data;
			JANUS_LOG(LOG_VERB, "    [%s]\n", c->name ? c->name : "??");
			if(c->items) {
				GList *li = c->items;
				while(li) {
					janus_config_item *i = (janus_config_item *)li->data;
					JANUS_LOG(LOG_VERB, "        %s: %s\n", i->name ? i->name : "??", i->value ? i->value : "??");
					li = li->next;
				}
			}
			l = l->next;
		}
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
			NULL, (yaml_char_t *)"tag:yaml.org,2002:map", 1,
			YAML_BLOCK_MAPPING_STYLE);
		yaml_emitter_emit(&emitter, &output_event);
	}
	/* Go on with the configuration */
	if(config->items) {
		GList *l = config->items;
		while(l) {
			janus_config_item *i = (janus_config_item *)l->data;
			if(i->name && i->value) {
				if(config->is_yaml) {
					yaml_scalar_event_initialize(&output_event,
						NULL, (yaml_char_t *)"tag:yaml.org,2002:str", (yaml_char_t *)i->name,
						-1, 1, 1, YAML_PLAIN_SCALAR_STYLE);
					yaml_emitter_emit(&emitter, &output_event);
					yaml_scalar_event_initialize(&output_event,
						NULL, (yaml_char_t *)"tag:yaml.org,2002:str", (yaml_char_t *)i->value,
						-1, 1, 1, YAML_PLAIN_SCALAR_STYLE);
					yaml_emitter_emit(&emitter, &output_event);
				} else {
					fwrite(i->name, sizeof(char), strlen(i->name), file);
					fwrite(" = ", sizeof(char), 3, file);
					/* If the value contains a semicolon, escape it */
					if(strchr(i->value, ';')) {
						char *value = g_strdup(i->value);
						value = janus_string_replace((char *)value, ";", "\\;");
						fwrite(value, sizeof(char), strlen(value), file);
						fwrite("\n", sizeof(char), 1, file);
						g_free(value);
					} else {
						/* No need to escape */
						fwrite(i->value, sizeof(char), strlen(i->value), file);
						fwrite("\n", sizeof(char), 1, file);
					}
				}
			}
			l = l->next;
		}
	}
	if(config->categories) {
		GList *l = config->categories;
		while(l) {
			janus_config_category *c = (janus_config_category *)l->data;
			if(c->name) {
				if(config->is_yaml) {
					yaml_scalar_event_initialize(&output_event,
						NULL, (yaml_char_t *)"tag:yaml.org,2002:str", (yaml_char_t *)c->name,
						-1, 1, 1, YAML_PLAIN_SCALAR_STYLE);
					yaml_emitter_emit(&emitter, &output_event);
				} else {
					fwrite("[", sizeof(char), 1, file);
					fwrite(c->name, sizeof(char), strlen(c->name), file);
					fwrite("]\n", sizeof(char), 2, file);
				}
				if(c->items == NULL) {
					/* Empty category */
					if(config->is_yaml) {
						yaml_scalar_event_initialize(&output_event,
							NULL, (yaml_char_t *)"tag:yaml.org,2002:str", (yaml_char_t *)"",
							-1, 1, 1, YAML_PLAIN_SCALAR_STYLE);
						yaml_emitter_emit(&emitter, &output_event);
					}
				} else {
					/* None-empty category */
					if(config->is_yaml) {
						yaml_mapping_start_event_initialize(&output_event,
							NULL, (yaml_char_t *)"tag:yaml.org,2002:map", 1,
							YAML_BLOCK_MAPPING_STYLE);
						yaml_emitter_emit(&emitter, &output_event);
					}
					GList *li = c->items;
					while(li) {
						janus_config_item *i = (janus_config_item *)li->data;
						if(i->name && i->value) {
							if(config->is_yaml) {
								yaml_scalar_event_initialize(&output_event,
									NULL, (yaml_char_t *)"tag:yaml.org,2002:str", (yaml_char_t *)i->name,
									-1, 1, 1, YAML_PLAIN_SCALAR_STYLE);
								yaml_emitter_emit(&emitter, &output_event);
								yaml_scalar_event_initialize(&output_event,
									NULL, (yaml_char_t *)"tag:yaml.org,2002:str", (yaml_char_t *)i->value,
									-1, 1, 1, YAML_PLAIN_SCALAR_STYLE);
								yaml_emitter_emit(&emitter, &output_event);
							} else {
								fwrite(i->name, sizeof(char), strlen(i->name), file);
								fwrite(" = ", sizeof(char), 3, file);
								/* If the value contains a semicolon, escape it */
								if(strchr(i->value, ';')) {
									char *value = g_strdup(i->value);
									value = janus_string_replace((char *)value, ";", "\\;");
									fwrite(value, sizeof(char), strlen(value), file);
									fwrite("\n", sizeof(char), 1, file);
									g_free(value);
								} else {
									/* No need to escape */
									fwrite(i->value, sizeof(char), strlen(i->value), file);
									fwrite("\n", sizeof(char), 1, file);
								}
							}
						}
						li = li->next;
					}
					/* TODO: implement subcategories */
					if(config->is_yaml) {
						yaml_mapping_end_event_initialize(&output_event);
						yaml_emitter_emit(&emitter, &output_event);
					}
				}
			}
			if(!config->is_yaml)
				fwrite("\r\n", sizeof(char), 2, file);
			l = l->next;
		}
	}
	/* If this is a YAML output file, do some preparations */
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
	if(config->items) {
		g_list_free_full(config->items, janus_config_free_item);
		config->items = NULL;
	}
	if(config->categories) {
		g_list_free_full(config->categories, janus_config_free_category);
		config->categories = NULL;
	}
	if(config->name)
		g_free((gpointer)config->name);
	g_free((gpointer)config);
	config = NULL;
}

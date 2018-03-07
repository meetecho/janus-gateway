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
		GList *cats = NULL, *last = NULL;
		janus_config_category *cg = NULL, *pc = NULL;
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
					/* Create category or subcategory */
					if(name != NULL) {
						if(depth == 2) {
							/* Main category */
							cg = janus_config_add_category(jc, NULL, name);
							cats = g_list_append(cats, cg);
						} else {
							/* Subcategory */
							pc = cg;
							cg = janus_config_add_category(jc, pc, name);
							cats = g_list_append(cats, cg);
						}
						if(cg == NULL) {
							JANUS_LOG(LOG_ERR, "Error adding category %s (%s)\n", event.data.scalar.value, filename);
							error = TRUE;
							break;
						}
						g_free(name);
						name = NULL;
					}
					/* TODO: add support for more innested categories and items */
					break;
				case YAML_MAPPING_END_EVENT:
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
					/* TODO: support more innested stuff for the future (API-wise too) */
					value = (char *)event.data.scalar.value;
					/* New category or category-level attribute? */
					if(value == NULL || strlen(value) == 0 || !strcmp(value, "null")) {
						/* Create empty category */
						if(name != NULL) {
							pc = cg;
							cg = janus_config_add_category(jc, pc, name);
							if(cg == NULL) {
								JANUS_LOG(LOG_ERR, "Error adding category %s (%s)\n", value, filename);
								error = TRUE;
								break;
							}
							g_free(name);
							name = NULL;
							cg = pc;
						}
						break;
					}
					if(name != NULL) {
						if(janus_config_add_item(jc, cg, name, value) == NULL) {
							JANUS_LOG(LOG_ERR, "Error adding item %s (%s)\n", name, filename);
							error = TRUE;
							break;
						}
						g_free(name);
						name = NULL;
					} else {
						name = g_strdup(value);
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
			cg = janus_config_add_category(jc, NULL, line);
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
			if(janus_config_add_item(jc, cg, name, value) == NULL) {
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

GList *janus_config_get_categories(janus_config *config, janus_config_category *parent) {
	if(config == NULL)
		return NULL;
	return parent ? parent->subcategories : config->categories;
}

janus_config_category *janus_config_get_category(janus_config *config, ...) {
	if(config == NULL)
		return NULL;
	va_list args;
	va_start(args, config);
	const char *name = va_arg(args, const char *);
	if(name == NULL) {
		va_end(args);
		return NULL;
	}
	GList *lc = config->categories;
	janus_config_category *pc = NULL, *c = NULL;
	while(name) {
		GList *tlc = lc;
		while(tlc) {
			pc = (janus_config_category *)tlc->data;
			if(pc && pc->category && pc->name && !strcasecmp(name, pc->name)) {
				/* Category found, dig deeper */
				break;
			}
			pc = NULL;
			tlc = tlc->next;
		}
		if(pc == NULL) {
			/* Category not found */
			c = NULL;
			break;
		}
		lc = pc->subcategories;
		c = pc;
		pc = NULL;
		/* Next parent */
		name = va_arg(args, const char *);
	}
	va_end(args);
	return c;
}

GList *janus_config_get_items(janus_config_category *category) {
	if(category == NULL)
		return NULL;
	return category->items;
}

janus_config_item *janus_config_get_item(janus_config_category *category, const char *name) {
	if(category == NULL || category->items == NULL || name == NULL)
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

janus_config_category *janus_config_add_category(janus_config *config, janus_config_category *parent, const char *category) {
	if(config == NULL || category == NULL)
		return NULL;
	janus_config_category *c = NULL;
	if(parent != NULL) {
		GList *l = parent->subcategories;
		while(l) {
			c = (janus_config_category *)l->data;
			if(c && c->category && c->name && !strcasecmp(category, c->name)) {
				/* Category exists, return this */
				return c;
			}
			l = l->next;
		}
	} else {
		c = janus_config_get_category(config, category, NULL);
		if(c != NULL) {
			/* Category exists, return this */
			return c;
		}
	}
	c = g_malloc0(sizeof(janus_config_category));
	c->category = TRUE;
	c->name = g_strdup(category);
	if(parent != NULL) {
		parent->subcategories = g_list_append(parent->subcategories, c);
	} else {
		config->categories = g_list_append(config->categories, c);
	}
	return c;
}

int janus_config_remove_category(janus_config *config, janus_config_category *parent, const char *category) {
	if(config == NULL || category == NULL)
		return -1;
	janus_config_category *c = NULL;
	if(parent != NULL) {
		GList *l = parent->subcategories;
		while(l) {
			c = (janus_config_category *)l->data;
			if(c && c->category && c->name && !strcasecmp(category, c->name)) {
				/* Found */
				parent->subcategories = g_list_remove(parent->subcategories, c);
				janus_config_free_category(c);
				return 0;
			}
			l = l->next;
		}
	} else {
		c = janus_config_get_category(config, category, NULL);
		if(c) {
			/* Found */
			config->categories = g_list_remove(config->categories, c);
			janus_config_free_category(c);
			return 0;
		}
	}
	return -2;
}

janus_config_item *janus_config_add_item(janus_config *config, janus_config_category *c, const char *name, const char *value) {
	if(config == NULL || name == NULL || value == NULL)
		return NULL;
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

int janus_config_remove_item(janus_config *config, janus_config_category *c, const char *name) {
	if(config == NULL || c == NULL || name == NULL)
		return -1;
	janus_config_item *item = janus_config_get_item(c, name);
	if(item == NULL)
		return -2;
	c->items = g_list_remove(c->items, item);
	janus_config_free_item(item);
	return 0;
}

void janus_config_print(janus_config *config) {
	janus_config_print_as(config, LOG_VERB);
}

static void janus_config_print_items(int level, GList *l, int indent) {
	while(l) {
		janus_config_item *i = (janus_config_item *)l->data;
		JANUS_LOG(level, "%*s%s: %s\n", indent, "",
			i->name ? i->name : "??", i->value ? i->value : "??");
		l = l->next;
	}
}

#define JANUS_CONFIG_INDENT 4
static void janus_config_print_categories(int level, GList *l, int indent) {
	while(l) {
		janus_config_category *c = (janus_config_category *)l->data;
		JANUS_LOG(level, "%*s[%s]\n", indent, "",
			c->name ? c->name : "??");
		if(c->items)
			janus_config_print_items(level, c->items, indent+JANUS_CONFIG_INDENT);
		if(c->subcategories)
			janus_config_print_categories(level, c->subcategories, indent+JANUS_CONFIG_INDENT);
		l = l->next;
	}
}

void janus_config_print_as(janus_config *config, int level) {
	if(config == NULL)
		return;
	JANUS_LOG(level, "[%s]\n", config->name ? config->name : "??");
	if(config->items)
		janus_config_print_items(level, config->items, JANUS_CONFIG_INDENT);
	if(config->categories)
		janus_config_print_categories(level, config->categories, JANUS_CONFIG_INDENT);
}

static void janus_config_save_items(janus_config *config, FILE *file, GList *items, yaml_emitter_t *emitter) {
	if(config == NULL || file == NULL || items == NULL )
		return;
	GList *l = items;
	yaml_event_t output_event;
	while(l) {
		janus_config_item *i = (janus_config_item *)l->data;
		if(i->name && i->value) {
			if(config->is_yaml) {
				yaml_scalar_event_initialize(&output_event,
					NULL, (yaml_char_t *)"tag:yaml.org,2002:str", (yaml_char_t *)i->name,
					-1, 1, 1, YAML_PLAIN_SCALAR_STYLE);
				yaml_emitter_emit(emitter, &output_event);
				yaml_scalar_event_initialize(&output_event,
					NULL, (yaml_char_t *)"tag:yaml.org,2002:str", (yaml_char_t *)i->value,
					-1, 1, 1, YAML_PLAIN_SCALAR_STYLE);
				yaml_emitter_emit(emitter, &output_event);
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

static void janus_config_save_categories(janus_config *config, FILE *file, GList *categories, yaml_emitter_t *emitter) {
	if(config == NULL || file == NULL || categories == NULL)
		return;
	GList *l = categories;
	yaml_event_t output_event;
	while(l) {
		janus_config_category *c = (janus_config_category *)l->data;
		if(c->name) {
			if(config->is_yaml) {
				yaml_scalar_event_initialize(&output_event,
					NULL, (yaml_char_t *)"tag:yaml.org,2002:str", (yaml_char_t *)c->name,
					-1, 1, 1, YAML_PLAIN_SCALAR_STYLE);
				yaml_emitter_emit(emitter, &output_event);
			} else {
				fwrite("[", sizeof(char), 1, file);
				fwrite(c->name, sizeof(char), strlen(c->name), file);
				fwrite("]\n", sizeof(char), 2, file);
			}
			if(c->items == NULL && c->subcategories == NULL) {
				/* Empty category */
				if(config->is_yaml) {
					yaml_scalar_event_initialize(&output_event,
						NULL, (yaml_char_t *)"tag:yaml.org,2002:str", (yaml_char_t *)"",
						-1, 1, 1, YAML_PLAIN_SCALAR_STYLE);
					yaml_emitter_emit(emitter, &output_event);
				}
			} else {
				/* None-empty category */
				if(config->is_yaml) {
					yaml_mapping_start_event_initialize(&output_event,
						NULL, (yaml_char_t *)"tag:yaml.org,2002:map", 1,
						YAML_BLOCK_MAPPING_STYLE);
					yaml_emitter_emit(emitter, &output_event);
				}
				if(c->items)
					janus_config_save_items(config, file, c->items, emitter);
				if(c->subcategories) {
					if(!config->is_yaml) {
						/* INI files don't support indented categories */
						JANUS_LOG(LOG_WARN, "Dropping subcategories of %s (unsupported in INI files)\n", c->name);
					} else {
						janus_config_save_categories(config, file, c->subcategories, emitter);
					}
				}
				/* Done */
				if(config->is_yaml) {
					yaml_mapping_end_event_initialize(&output_event);
					yaml_emitter_emit(emitter, &output_event);
				}
			}
		}
		if(!config->is_yaml)
			fwrite("\r\n", sizeof(char), 2, file);
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
			NULL, (yaml_char_t *)"tag:yaml.org,2002:map", 1,
			YAML_BLOCK_MAPPING_STYLE);
		yaml_emitter_emit(&emitter, &output_event);
	}
	/* Go on with the configuration */
	if(config->items)
		janus_config_save_items(config, file, config->items, &emitter);
	if(config->categories)
		janus_config_save_categories(config, file, config->categories, &emitter);
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

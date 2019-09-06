/*! \file    config.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Configuration files parsing
 * \details  Implementation of a parser of INI and libconfig configuration files.
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

#include <libconfig.h>

#include "config.h"
#include "debug.h"
#include "utils.h"


/* Filename helper */
static char *get_filename(char *path) {
	return basename(path);
}

static gboolean is_jcfg_config(const char *path) {
	if(path == NULL)
		return FALSE;
	return strstr(path, ".jcfg") != NULL;
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


/* Helper to recursively process a libconfig setting */
static int janus_config_jfcg_parse(janus_config *config, janus_config_container *parent, config_setting_t *setting) {
	if(!config || !setting)
		return -1;
	switch(config_setting_type(setting)) {
		case CONFIG_TYPE_INT: {
			const char *name = config_setting_name(setting);
			int val = config_setting_get_int(setting);
			char value[50];
			g_snprintf(value, sizeof(value), "%d", val);
			janus_config_item *item = janus_config_item_create(name, value);
			if(janus_config_add(config, parent, item) < 0) {
				janus_config_container_destroy(item);
				JANUS_LOG(LOG_ERR, "Error adding item %s to %s\n", name, parent ? parent->name : "root");
				return -1;
			}
			break;
		}
		case CONFIG_TYPE_INT64: {
			const char *name = config_setting_name(setting);
			long long val = config_setting_get_int64(setting);
			char value[50];
			g_snprintf(value, sizeof(value), "%lld", val);
			janus_config_item *item = janus_config_item_create(name, value);
			if(janus_config_add(config, parent, item) < 0) {
				janus_config_container_destroy(item);
				JANUS_LOG(LOG_ERR, "Error adding item %s to %s\n", name, parent ? parent->name : "root");
				return -1;
			}
			break;
		}
		case CONFIG_TYPE_FLOAT: {
			const char *name = config_setting_name(setting);
			double val = config_setting_get_float(setting);
			char value[50];
			g_snprintf(value, sizeof(value), "%f", val);
			janus_config_item *item = janus_config_item_create(name, value);
			if(janus_config_add(config, parent, item) < 0) {
				janus_config_container_destroy(item);
				JANUS_LOG(LOG_ERR, "Error adding item %s to %s\n", name, parent ? parent->name : "root");
				return -1;
			}
			break;
		}
		case CONFIG_TYPE_STRING: {
			const char *name = config_setting_name(setting);
			const char *value = config_setting_get_string(setting);
			janus_config_item *item = janus_config_item_create(name, value);
			if(janus_config_add(config, parent, item) < 0) {
				janus_config_container_destroy(item);
				JANUS_LOG(LOG_ERR, "Error adding item %s to %s\n", name, parent ? parent->name : "root");
				return -1;
			}
			break;
		}
		case CONFIG_TYPE_BOOL: {
			const char *name = config_setting_name(setting);
			gboolean val = config_setting_get_bool(setting);
			janus_config_item *item = janus_config_item_create(name, val ? "true" : "false");
			if(janus_config_add(config, parent, item) < 0) {
				janus_config_container_destroy(item);
				JANUS_LOG(LOG_ERR, "Error adding item %s to %s\n", name, parent ? parent->name : "root");
				return -1;
			}
			break;
		}
		case CONFIG_TYPE_ARRAY:
		case CONFIG_TYPE_LIST:
		case CONFIG_TYPE_GROUP: {
			int num = config_setting_length(setting);
			if(num > 0) {
				int i=0;
				for(i=0; i<num; i++) {
					config_setting_t *elem = config_setting_get_elem(setting, i);
					if(elem == NULL) {
						JANUS_LOG(LOG_WARN, "Couldn't access element #%d of setting '%s'...\n", i, config_setting_name(setting));
						continue;
					}
					const char *name = config_setting_name(elem);
					if(config_setting_type(elem) == CONFIG_TYPE_ARRAY || config_setting_type(elem) == CONFIG_TYPE_LIST) {
						/* Create an array and parse it */
						janus_config_category *cg = janus_config_array_create(name);
						if(janus_config_add(config, parent, cg) < 0) {
							JANUS_LOG(LOG_ERR, "Error adding array %s to %s\n", name, parent ? parent->name : "root");
							janus_config_container_destroy(cg);
							return -1;
						}
						int res = janus_config_jfcg_parse(config, cg, elem);
						if(res < 0)
							return res;
					} else if(config_setting_type(elem) == CONFIG_TYPE_GROUP) {
						/* Create a category and parse it */
						janus_config_category *cg = janus_config_category_create(name);
						if(janus_config_add(config, parent, cg) < 0) {
							JANUS_LOG(LOG_ERR, "Error adding category %s to %s\n", name, parent ? parent->name : "root");
							janus_config_container_destroy(cg);
							return -1;
						}
						int res = janus_config_jfcg_parse(config, cg, elem);
						if(res < 0)
							return res;
					} else {
						int res = janus_config_jfcg_parse(config, parent, elem);
						if(res < 0)
							return res;
					}
				}
			}
			break;
		}
		default:
			break;
	}
	return 0;
}

/* Parse a configuration file */
janus_config *janus_config_parse(const char *config_file) {
	if(config_file == NULL)
		return NULL;
	char *tmp_filename = g_strdup(config_file);
	char *filename = get_filename(tmp_filename);
	if(filename == NULL) {
		JANUS_LOG(LOG_ERR, "Invalid filename %s\n", config_file);
		g_free(tmp_filename);
		return NULL;
	}
	/* Open file */
	FILE *file = fopen(config_file, "rt");
	if(!file) {
		JANUS_LOG(LOG_ERR, "  -- Error reading configuration file '%s'... error %d (%s)\n", filename, errno, strerror(errno));
		g_free(tmp_filename);
		return NULL;
	}
	/* Create configuration instance */
	janus_config *jc = g_malloc0(sizeof(janus_config));
	jc->name = g_strdup(filename);
	/* Is this a libconfig or INI config file? */
	jc->is_jcfg = is_jcfg_config(jc->name);
	if(jc->is_jcfg) {
		/* Parse with libconfig and not manually */
		config_t config;
		config_init(&config);
		if(config_read(&config, file) == CONFIG_FALSE) {
			JANUS_LOG(LOG_ERR, "Error parsing config file at line %d: %s\n",
				config_error_line(&config), config_error_text(&config));
			config_destroy(&config);
			goto error;
		}
		/* Traverse the document */
		config_setting_t *root = config_root_setting(&config);
		if(janus_config_jfcg_parse(jc, NULL, root) < 0) {
			JANUS_LOG(LOG_ERR, "Error parsing config file at line %d: %s\n",
				config_error_line(&config), config_error_text(&config));
			config_destroy(&config);
			goto error;
		}
		config_destroy(&config);
		/* We're done */
		goto done;
	}
	/* Not libconfig: assume INI, traverse manually and parse it */
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
	/* Is this a libconfig or INI config file? */
	jc->is_jcfg = is_jcfg_config(jc->name);
	return jc;
}


/* Containers management */
janus_config_item *janus_config_item_create(const char *name, const char *value) {
	if(name == NULL && value == NULL)
		return NULL;
	janus_config_item *item = g_malloc0(sizeof(janus_config_item));
	item->type = janus_config_type_item;
	if(name)
		item->name = g_strdup(name);
	if(value)
		item->value = g_strdup(value);
	return item;
}

janus_config_category *janus_config_category_create(const char *name) {
	janus_config_category *category = g_malloc0(sizeof(janus_config_category));
	category->type = janus_config_type_category;
	if(name != NULL)
		category->name = g_strdup(name);
	return category;
}

janus_config_array *janus_config_array_create(const char *name) {
	janus_config_array *array = g_malloc0(sizeof(janus_config_array));
	array->type = janus_config_type_array;
	if(name != NULL)
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
		} else if(type == janus_config_type_array) {
			c = janus_config_array_create(name);
		} else {
			JANUS_LOG(LOG_WARN, "Not a category and not an array, not creating anything...\n");
		}
		if(c != NULL && janus_config_add(config, parent, c) < 0) {
			janus_config_container_destroy(c);
			JANUS_LOG(LOG_ERR, "Error adding item %s to %s\n", name, parent ? parent->name : "root");
			return NULL;
		}
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
	if(item->name) {
		/* Remove any existing property with the same name in that container first, if any */
		janus_config_remove(config, container, item->name);
	}
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
			JANUS_LOG(level, "%*s%s%s%s\n", indent, "",
				c->name ? c->name : "",
				c->name && c->value ? ": " : "",
				c->value ? c->value : "");
		} else if(c->type == janus_config_type_category) {
			JANUS_LOG(level, "%*s%s%s{\n", indent, "",
				c->name ? c->name : "",
				c->name ? ": " : "");
			if(c->list)
				janus_config_print_list(level, c->list, indent+JANUS_CONFIG_INDENT);
			JANUS_LOG(level, "%*s}\n", indent, "");
		} else if(c->type == janus_config_type_array) {
			JANUS_LOG(level, "%*s%s%s[\n", indent, "",
				c->name ? c->name : "",
				c->name ? ": " : "");
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

static void janus_config_save_list(janus_config *config, FILE *file, int level, gboolean array, GList *list, config_setting_t *lcfg) {
	if(config == NULL || file == NULL || list == NULL )
		return;
	GList *l = list;
	config_setting_t *elem = NULL;
	while(l) {
		janus_config_container *c = (janus_config_container *)l->data;
		if(c->type == janus_config_type_item) {
			if(config->is_jcfg) {
				elem = config_setting_add(lcfg, c->name, CONFIG_TYPE_STRING);
				if(elem == NULL) {
					JANUS_LOG(LOG_ERR, "Error saving string '%s' to the config file...\n", c->name);
					l = l->next;
					continue;
				}
				config_setting_set_string(elem, c->value);
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
			if(config->is_jcfg) {
				elem = config_setting_add(lcfg, c->name, CONFIG_TYPE_GROUP);
				if(elem == NULL) {
					JANUS_LOG(LOG_ERR, "Error saving group '%s' to the config file...\n", c->name);
					l = l->next;
					continue;
				}
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
			if(c->list != NULL) {
				/* Non-empty category */
				janus_config_save_list(config, file, level+1, FALSE, c->list, elem);
			}
			if(!config->is_jcfg)
				fwrite("\r\n", sizeof(char), 2, file);
		} else if(c->type == janus_config_type_array) {
			if(!config->is_jcfg) {
				/* INI files don't support arrays */
				JANUS_LOG(LOG_WARN, "Dropping array %s (unsupported in INI files)\n", c->name);
			} else {
				/* FIXME We don't know in advance if all items will be of the
				 * same kind, so we use list instead of array in libconfig */
				elem = config_setting_add(lcfg, c->name, CONFIG_TYPE_LIST);
				if(elem == NULL) {
					JANUS_LOG(LOG_ERR, "Error saving list '%s' to the config file...\n", c->name);
					l = l->next;
					continue;
				}
				if(c->list != NULL) {
					/* Non-empty array */
					janus_config_save_list(config, file, level+1, FALSE, c->list, elem);
				}
			}
		}
		l = l->next;
	}
}

gboolean janus_config_save(janus_config *config, const char *folder, const char *filename) {
	if(config == NULL)
		return -1;
	/* If this is a libconfig configuration, create an object for it */
	config_t lcfg;
	if(config->is_jcfg)
		config_init(&lcfg);
	/* Open the file */
	FILE *file = NULL;
	char path[1024];
	if(folder != NULL) {
		/* Create folder, if needed */
		if(janus_mkdir(folder, 0755) < 0) {
			JANUS_LOG(LOG_ERR, "Couldn't save configuration file, error creating folder '%s'...\n", folder);
			if(config->is_jcfg)
				config_destroy(&lcfg);
			return -2;
		}
		g_snprintf(path, 1024, "%s/%s.%s", folder, filename, config->is_jcfg ? "jcfg" : "cfg");
	} else {
		g_snprintf(path, 1024, "%s.%s", filename, config->is_jcfg ? "jcfg" : "cfg");
	}
	file = fopen(path, "wt");
	if(file == NULL) {
		JANUS_LOG(LOG_ERR, "Couldn't save configuration file, error opening file '%s'...\n", path);
		if(config->is_jcfg)
			config_destroy(&lcfg);
		return -3;
	}
	/* Print a header/comment */
	char date[64], header[256];
	struct tm tmresult;
	time_t ltime = time(NULL);
	localtime_r(&ltime, &tmresult);
	strftime(date, sizeof(date), "%a %b %e %T %Y", &tmresult);
	char comment = config->is_jcfg ? '#' : ';';
	g_snprintf(header, 256, "%c\n%c File automatically generated on %s\n%c\n\n",
		comment, comment, date, comment);
	fwrite(header, sizeof(char), strlen(header), file);
	/* Go on with the configuration */
	if(config->list)
		janus_config_save_list(config, file, 0, FALSE, config->list, config->is_jcfg ? config_root_setting(&lcfg) : NULL);
	/* If this is a libconfig output file, save and destroy the object */
	if(config->is_jcfg) {
		config_write(&lcfg, file);
		config_destroy(&lcfg);
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
	g_free((gpointer)config->name);
	g_free((gpointer)config);
	config = NULL;
}

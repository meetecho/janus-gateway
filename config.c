/*! \file    config.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Configuration files parsing
 * \details  Implementation of a parser of INI configuration files.
 * 
 * \ingroup core
 * \ref core
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "config.h"
#include "debug.h"
#include "utils.h"


/* Filename helper */
static char *get_filename(const char *path) {
	char *filename = NULL;
	if(path)
		filename = strrchr(path, '/')+1;
	return filename;
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
		g_free((gpointer)i->name);
		g_free((gpointer)i->value);
		g_free(i);
	}
}

static void janus_config_free_category(gpointer data) {
	janus_config_category *c = (janus_config_category *)data;
	if(c) {
		g_free((gpointer)c->name);
		if(c->items)
			g_list_free_full(c->items, janus_config_free_item);
		g_free(c);
	}
}


/* Public methods */
janus_config *janus_config_parse(const char *config_file) {
	if(config_file == NULL)
		return NULL;
	char *filename = get_filename(config_file);
	if(filename == NULL) {
		JANUS_LOG(LOG_ERR, "Invalid filename %s\n", config_file);
		return NULL;
	}
	/* Open file */
	FILE *file = fopen(config_file, "rt");
	if(!file) {
		JANUS_LOG(LOG_ERR, "  -- Error reading configuration file '%s'... error %d (%s)\n", filename, errno, strerror(errno));
		return NULL;
	}
	/* Create configuration instance */
	janus_config *jc = g_malloc0(sizeof(janus_config));
	jc->name = g_strdup(filename);
	/* Traverse and parse it */
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
	fclose(file);
	return jc;

error:
	fclose(file);
	janus_config_destroy(jc);
	return NULL;
}

janus_config *janus_config_create(const char *name) {
	janus_config *jc = g_malloc0(sizeof(janus_config));
	if(name != NULL) {
		jc->name = g_strdup(name);
	}
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
		if(c && c->name && !strcasecmp(name, c->name))
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
	FILE *file = NULL;
	char path[1024];
	if(folder != NULL) {
		/* Create folder, if needed */
		if(janus_mkdir(folder, 0755) < 0) {
			JANUS_LOG(LOG_ERR, "Couldn't save configuration file, error creating folder '%s'...\n", folder);
			return -2;
		}
		g_snprintf(path, 1024, "%s/%s.cfg", folder, filename);
	} else {
		g_snprintf(path, 1024, "%s.cfg", filename);
	}
	file = fopen(path, "wt");
	if(file == NULL) {
		JANUS_LOG(LOG_ERR, "Couldn't save configuration file, error opening file '%s'...\n", path);
		return -3;
	}
	/* Print a header */
	char date[64], header[256];
	struct tm tmresult;
	time_t ltime = time(NULL);
	localtime_r(&ltime, &tmresult);
	strftime(date, sizeof(date), "%a %b %e %T %Y", &tmresult);
	g_snprintf(header, 256, ";\n; File automatically generated on %s\n;\n\n", date);
	fwrite(header, sizeof(char), strlen(header), file);
	/* Go on with the configuration */
	if(config->items) {
		GList *l = config->items;
		while(l) {
			janus_config_item *i = (janus_config_item *)l->data;
			if(i->name && i->value) {
				fwrite(i->name, sizeof(char), strlen(i->name), file);
				fwrite(" = ", sizeof(char), 3, file);
				fwrite(i->value, sizeof(char), strlen(i->value), file);
				fwrite("\n", sizeof(char), 1, file);
			}
			l = l->next;
		}
	}
	if(config->categories) {
		GList *l = config->categories;
		while(l) {
			janus_config_category *c = (janus_config_category *)l->data;
			if(c->name) {
				fwrite("[", sizeof(char), 1, file);
				fwrite(c->name, sizeof(char), strlen(c->name), file);
				fwrite("]\n", sizeof(char), 2, file);
				if(c->items) {
					GList *li = c->items;
					while(li) {
						janus_config_item *i = (janus_config_item *)li->data;
						if(i->name && i->value) {
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
						li = li->next;
					}
				}
			}
			fwrite("\r\n", sizeof(char), 2, file);
			l = l->next;
		}
	}
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
	g_free((gpointer)config->name);
	g_free((gpointer)config);
	config = NULL;
}

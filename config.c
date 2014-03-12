/*! \file    config.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \brief    Configuration files parsing
 * \details  Implementation of a parser of INI configuration files (based on libini-config).
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


/* Filename helper */
char *get_filename(const char *path);
char *get_filename(const char *path)
{
	char *filename = NULL;
	if(path) {
		filename = strrchr(path, '/')+1;
	}

	return filename;
}

/* Trimming helper */
char *ltrim(char *s);
char *ltrim(char *s)
{
    while(isspace(*s)) s++;
    return s;
}

char *rtrim(char *s);
char *rtrim(char *s)
{
    char* back = s + strlen(s);
    while(isspace(*--back));
    *(back+1) = '\0';
    return s;
}

char *trim(char *s);
char *trim(char *s)
{
    return rtrim(ltrim(s)); 
}


janus_config *janus_config_parse(const char *config_file) {
	if(config_file == NULL)
		return NULL;
	char *filename = get_filename(config_file);
	if(filename == NULL) {
		JANUS_DEBUG("Invalid filename %s\n", config_file);
		return NULL;
	}
	janus_config *jc = NULL;
	janus_config_category *cg = NULL;
	janus_config_item *ci = NULL;
	struct collection_item *config = NULL;
	struct collection_item *config_errors = NULL;
	int res = config_from_file(filename, config_file, &config, INI_STOP_ON_ERROR, &config_errors);
	if(res != 0) {
		JANUS_DEBUG("  -- Error reading configuration file... error %d (%s)\n", res, strerror(res));
	}
	if(config == NULL && config_errors != NULL) {
		/* Configuration parsing error */
		struct collection_iterator *iterator = NULL;
		res = col_bind_iterator(&iterator, config_errors, 0);
		if(res != 0) {
			JANUS_DEBUG("  -- Error parsing configuration file... error %d (%s)\n", res, strerror(res));
			free_ini_config_errors(config_errors);
			return NULL;
		}
		int len = 0;
		struct collection_item *item = NULL;
		while(1) {
			item = NULL;
			len = 0;
			res = col_iterate_collection(iterator, &item);
			if(res != 0 || item == NULL)
				break;
			if(col_get_item_type(item) == COL_TYPE_COLLECTION) {
				JANUS_PRINT("[%s]\n", col_get_item_property(item, &len));
			} else if(col_get_item_type(item) == COL_TYPE_COLLECTIONREF) {
				JANUS_PRINT("    [%s]\n", col_get_item_property(item, &len));
			} else {
				JANUS_PRINT("        %s: %s\n", col_get_item_property(item, &len), (const char *)col_get_item_data(item));
			}
		};
	}
	if(config != NULL) {
		struct collection_iterator *iterator = NULL;
		res = col_bind_iterator(&iterator, config, 0);
		if(res != 0) {
			JANUS_DEBUG("  -- Error parsing configuration file... error %d (%s)\n", res, strerror(res));
			free_ini_config(config);
			if(config_errors != NULL)
				free_ini_config_errors(config_errors);
			return NULL;
		}
		jc = calloc(1, sizeof(janus_config));
		if(jc == NULL) {
			JANUS_DEBUG("Memory error!\n");
			return NULL;
		}
		jc->items = NULL;
		jc->categories = NULL;
		int len = 0;
		struct collection_item *item = NULL;
		char *name = NULL, *value = NULL, *temp = NULL, *c = NULL;
		while(1) {
			item = NULL;
			len = 0;
			res = col_iterate_collection(iterator, &item);
			if(res != 0 || item == NULL)
				break;
			name = (char *)col_get_item_property(item, &len);
			if(col_get_item_type(item) == COL_TYPE_COLLECTION) {
				/* Configuration name */
				//~ JANUS_PRINT("[%s]\n", name ? name : "??");
				if(name) {
					jc->name = g_strdup(name);
					if(jc->name == NULL) {
						JANUS_DEBUG("Memory error!\n");
						free_ini_config(config);
						if(config_errors != NULL)
							free_ini_config_errors(config_errors);
						janus_config_destroy(jc);
						return NULL;
					}
				}
			} else if(col_get_item_type(item) == COL_TYPE_COLLECTIONREF) {
				/* Configuration category */
				ci = NULL;
				janus_config_category *ncg = calloc(1, sizeof(janus_config_category));
				if(ncg == NULL) {
					JANUS_DEBUG("Memory error!\n");
					free_ini_config(config);
					if(config_errors != NULL)
						free_ini_config_errors(config_errors);
					janus_config_destroy(jc);
					return NULL;
				}
				ncg->name = NULL;
				ncg->items = NULL;
				ncg->next = NULL;
				//~ JANUS_PRINT("    [%s]\n", name ? name : "??");
				if(name) {
					ncg->name = g_strdup(name);
					if(ncg->name == NULL) {
						JANUS_DEBUG("Memory error!\n");
						free_ini_config(config);
						if(config_errors != NULL)
							free_ini_config_errors(config_errors);
						janus_config_destroy(jc);
						return NULL;
					}
				}
				if(jc->categories == NULL) {
					jc->categories = ncg;
				} else {
					cg->next = ncg;
				}
				cg = ncg;
			} else {
				/* Configuration item */
				temp = g_strdup((char *)col_get_item_data(item));
				if(temp == NULL) {
					JANUS_DEBUG("Memory error!\n");
					free_ini_config(config);
					if(config_errors != NULL)
						free_ini_config_errors(config_errors);
					janus_config_destroy(jc);
					return NULL;
				}
				if((c = strrchr(temp, ';')) != NULL)
					*c = '\0';
				value = trim(temp);
				janus_config_item *nci = calloc(1, sizeof(janus_config_item));
				if(nci == NULL) {
					JANUS_DEBUG("Memory error!\n");
					free_ini_config(config);
					if(config_errors != NULL)
						free_ini_config_errors(config_errors);
					janus_config_destroy(jc);
					return NULL;
				}
				nci->name = NULL;
				nci->value = NULL;
				nci->next = NULL;
				//~ JANUS_PRINT("        %s: %s\n", name ? name : "??", value ? value : "??");
				if(name) {
					nci->name = g_strdup(name);
					if(nci->name == NULL) {
						JANUS_DEBUG("Memory error!\n");
						free_ini_config(config);
						if(config_errors != NULL)
							free_ini_config_errors(config_errors);
						janus_config_destroy(jc);
						return NULL;
					}
				}
				if(value) {
					nci->value = g_strdup(value);
					g_free((gpointer)value);
					if(nci->value == NULL) {
						JANUS_DEBUG("Memory error!\n");
						free_ini_config(config);
						if(config_errors != NULL)
							free_ini_config_errors(config_errors);
						janus_config_destroy(jc);
						return NULL;
					}
				}
				if(cg == NULL) {
					/* Uncategorized item */
					if(jc->items == NULL) {
						jc->items = nci;
					} else {
						ci->next = nci;
					}
				} else {
					/* Att to current category */
					if(cg->items == NULL) {
						cg->items = nci;
					} else {
						ci->next = nci;
					}
				}
				ci = nci;
			}
		};
	}
	free_ini_config(config);
	if(config_errors != NULL)
		free_ini_config_errors(config_errors);
	return jc;
}

janus_config *janus_config_create(const char *name) {
	janus_config *jc = calloc(1, sizeof(janus_config));
	if(jc == NULL) {
		JANUS_DEBUG("Memory error!\n");
		return NULL;
	}
	if(name != NULL) {
		jc->name = g_strdup(name);
		if(jc->name == NULL) {
			JANUS_DEBUG("Memory error!\n");
			janus_config_destroy(jc);
			return NULL;
		}
	}
	return jc;
}

janus_config_category *janus_config_get_categories(janus_config *config) {
	if(config == NULL)
		return NULL;
	return config->categories;
}

janus_config_category *janus_config_get_category(janus_config *config, const char *name) {
	if(config == NULL || name == NULL)
		return NULL;
	if(config->categories == NULL)
		return NULL;
	janus_config_category *c = config->categories;
	while(c) {
		if(c->name && !strcasecmp(name, c->name))
			return c;
		c = c->next;
	}
	return NULL;
}

janus_config_item *janus_config_get_items(janus_config_category *category) {
	if(category == NULL)
		return NULL;
	return category->items;
}

janus_config_item *janus_config_get_item(janus_config_category *category, const char *name) {
	if(category == NULL || name == NULL)
		return NULL;
	if(category->items == NULL)
		return NULL;
	janus_config_item *i = category->items;
	while(i) {
		if(i->name && !strcasecmp(name, i->name))
			return i;
		i = i->next;
	}
	return NULL;
}

janus_config_item *janus_config_get_item_drilldown(janus_config *config, const char *category, const char *name) {
	if(config == NULL || category == NULL || name == NULL)
		return NULL;
	janus_config_category *c = janus_config_get_category(config, category);
	if(c == NULL)
		return NULL;
	if(c->items == NULL)
		return NULL;
	return janus_config_get_item(c, name);
}

janus_config_item *janus_config_add_item(janus_config *config, const char *category, const char *name, const char *value) {
	if(config == NULL || category == NULL || name == NULL || value == NULL)
		return NULL;
	janus_config_category *c = janus_config_get_category(config, category);
	if(c == NULL) {
		/* Create it */
		c = calloc(1, sizeof(janus_config_category));
		if(c == NULL) {
			JANUS_DEBUG("Memory error!\n");
			return NULL;
		}
		c->name = g_strdup(category);
		if(c->name == NULL) {
			JANUS_DEBUG("Memory error!\n");
			g_free((gpointer)c);
			return NULL;
		}
		c->next = NULL;
		if(config->categories == NULL) {
			config->categories = c;
		} else {
			janus_config_category *tmp = config->categories;
			while(tmp) {
				if(tmp->next == NULL) {
					tmp->next = c;
					break;
				}
				tmp = tmp->next;
			}
		}
	}
	janus_config_item *item = janus_config_get_item(c, name);
	if(item == NULL) {
		/* Create it */
		item = calloc(1, sizeof(janus_config_item));
		if(item == NULL) {
			JANUS_DEBUG("Memory error!\n");
			return NULL;
		}
		item->name = g_strdup(name);
		if(item->name == NULL) {
			JANUS_DEBUG("Memory error!\n");
			g_free((gpointer)item);
			return NULL;
		}
		item->value = g_strdup(value);
		if(item->value == NULL) {
			JANUS_DEBUG("Memory error!\n");
			g_free((gpointer)item->name);
			g_free((gpointer)item);
			return NULL;
		}
		item->next = NULL;
		if(c->items == NULL) {
			c->items = item;
		} else {
			janus_config_item *tmp = c->items;
			while(tmp) {
				if(tmp->next == NULL) {
					tmp->next = item;
					break;
				}
				tmp = tmp->next;
			}
		}
	} else {
		/* Update it */
		char *item_value = g_strdup(value);
		if(item_value == NULL) {
			JANUS_DEBUG("Memory error!\n");
			return NULL;
		}
		if(item->value)
			g_free((gpointer)item->value);
		item->value = item_value;
	}
	return item;
}

void janus_config_print(janus_config *config) {
	if(config == NULL)
		return;
	JANUS_PRINT("[%s]\n", config->name ? config->name : "??");
	if(config->items) {
		janus_config_item *i = config->items;
		config->items = NULL;
		while(i) {
			JANUS_PRINT("        %s: %s\n", i->name ? i->name : "??", i->value ? i->value : "??");
			i = i->next;
		}
	}
	if(config->categories) {
		janus_config_category *c = config->categories;
		while(c) {
			JANUS_PRINT("    [%s]\n", c->name ? c->name : "??");
			if(c->items) {
				janus_config_item *i = c->items;
				while(i) {
					JANUS_PRINT("        %s: %s\n", i->name ? i->name : "??", i->value ? i->value : "??");
					i = i->next;
				}
			}
			c = c->next;
		}
	}
	config = NULL;
}

void janus_config_destroy(janus_config *config) {
	if(config == NULL)
		return;
	if(config->items) {
		janus_config_item *i = config->items, *tmp = NULL;
		config->items = NULL;
		while(i) {
			if(i->name)
				g_free((gpointer)i->name);
			if(i->value)
				g_free((gpointer)i->value);
			tmp = i;
			i = i->next;
			g_free((gpointer)tmp);
			tmp = NULL;
		}
	}
	if(config->categories) {
		janus_config_category *c = config->categories, *tmp = NULL;
		config->categories = NULL;
		while(c) {
			if(c->name)
				g_free((gpointer)c->name);
			if(c->items) {
				janus_config_item *i = c->items, *tmp2 = NULL;
				c->items = NULL;
				while(i) {
					if(i->name)
						g_free((gpointer)i->name);
					if(i->value)
						g_free((gpointer)i->value);
					tmp2 = i;
					i = i->next;
					g_free((gpointer)tmp2);
					tmp2 = NULL;
				}
			}
			tmp = c;
			c = c->next;
			g_free((gpointer)tmp);
			tmp = NULL;
		}
	}
	if(config->name)
		g_free((gpointer)config->name);
	g_free((gpointer)config);
	config = NULL;
}

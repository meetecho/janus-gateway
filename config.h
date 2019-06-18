/*! \file    config.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Configuration files parsing (headers)
 * \details  Implementation of a parser of INI and libconfig configuration files.
 *
 * \ingroup core
 * \ref core
 */

#ifndef _JANUS_CONFIG_H
#define _JANUS_CONFIG_H

#include <glib.h>

/*! \brief Configuration element type */
typedef enum janus_config_type {
	/*! \brief Anything (just for searches) */
	janus_config_type_any = 1,
	/*! \brief Plain item */
	janus_config_type_item,
	/*! \brief Category */
	janus_config_type_category,
	/*! \brief Array */
	janus_config_type_array,
} janus_config_type;

/*! \brief Generic configuration container (can be an item, a category or an array) */
typedef struct janus_config_container {
	/*! \brief Whether this is a category, an item or an array */
	janus_config_type type;
	/*! \brief Name of the item/category/array */
	const char *name;
	/*! \brief Value of the item (item only) */
	const char *value;
	/*! \brief Linked list of contained items/categories/arrays (category and array only) */
	GList *list;
} janus_config_container;

/*! \brief Configuration item (defined for backwards compatibility) */
typedef struct janus_config_container janus_config_item;

/*! \brief Configuration category (defined for backwards compatibility) */
typedef struct janus_config_container janus_config_category;

/*! \brief Configuration array */
typedef struct janus_config_container janus_config_array;

/*! \brief Configuration container */
typedef struct janus_config {
	/*! \brief Whether this is a libconfig (jcfg for us) or an INI config */
	gboolean is_jcfg;
	/*! \brief Name of the configuration */
	const char *name;
	/*! \brief Linked list of items/categories/arrays */
	GList *list;
} janus_config;


/*! \brief Method to parse an INI configuration file
 * @param[in] config_file Path to the configuration file
 * @returns A pointer to a valid janus_config instance if successful, NULL otherwise */
janus_config *janus_config_parse(const char *config_file);
/*! \brief Method to create a new, empty, configuration
 * @param[in] name Name to give to the configuration
 * @returns A pointer to a valid janus_config instance if successful, NULL otherwise */
janus_config *janus_config_create(const char *name);
/*! \brief Helper method to print a configuration on the standard output
 * @note This prints with LOG_VERB: if you need the configuration to be visible at
 * a different debugging level, use janus_config_print_as instead
 * @param[in] config The configuration to print */
void janus_config_print(janus_config *config);
/*! \brief Helper method to print a configuration on the standard output
 * using a different logging level than LOG_VERB
 * @param[in] config The configuration to print
 * @param[in] level The debugging level to use */
void janus_config_print_as(janus_config *config, int level);
/*! \brief Helper method to save a configuration to a file
 * @param[in] config The configuration to sav
 * @param[in] folder The folder the file should be saved to
 * @param[in] filename The file name, extension included (should be .jcfg, or .cfg for legacy INI files)
 * @returns 0 if successful, a negative integer otherwise */
int janus_config_save(janus_config *config, const char *folder, const char *filename);
/*! \brief Destroy a configuration container instance
 * @param[in] config The configuration to destroy */
void janus_config_destroy(janus_config *config);

/*! \brief Method to create a new janus_config_item instance from name and value
 * @param[in] name Name to give to the item
 * @param[in] value Value of the item (optional)
 * @returns A valid janus_config_item instance if successful, NULL otherwise */
janus_config_item *janus_config_item_create(const char *name, const char *value);
/*! \brief Method to create a new janus_config_category instance
 * @param[in] name Name to give to the category
 * @returns A pointer to a valid janus_config_category instance if successful, NULL otherwise */
janus_config_category *janus_config_category_create(const char *name);
/*! \brief Method to create a new janus_config_array instance
 * @param[in] name Name to give to the array
 * @returns A valid janus_config_array instance if successful, NULL otherwise */
janus_config_array *janus_config_array_create(const char *name);
/*! \brief Helper method to quickly destroy an item, category or array
 * @note This method also destroys anything it contains, if it's a category or
 * array, but will not unlink the object from its parent: this is up to the caller
 * @param[in] container The item/category/array to destroy */
void janus_config_container_destroy(janus_config_container *container);

/*! \brief Helper method to quickly get an item, category, or array
 * @note If the parent container is NULL, the lookup is done at the root. If something is found
 * but type doesn't match (name is an array but we're looking for a category), NULL is returned.
 * @param[in] config The configuration instance
 * @param[in] parent The parent container (category or array), if any
 * @param[in] type The type of container to look for
 * @param[in] name The name of the item/category/array to look for
 * @returns A pointer to a valid janus_config_container instance if successful, NULL otherwise */
janus_config_container *janus_config_get(janus_config *config,
	janus_config_container *parent, janus_config_type type, const char *name);
/*! \brief Same as janus_config_get, but creates the element if it doesn't exist
 * @note Nothing is created if type is janus_config_type_any.
 * @param[in] config The configuration instance
 * @param[in] parent The parent container (category or array), if any
 * @param[in] type The type of container to look for
 * @param[in] name The name of the item/category/array to look for
 * @returns A pointer to a valid janus_config_container instance if successful, NULL otherwise */
janus_config_container *janus_config_get_create(janus_config *config,
	janus_config_container *parent, janus_config_type type, const char *name);
/*! \brief Helper method to quickly lookup an item, category, or array
 * @note If something is found but type doesn't match (name is an array
 * but we're looking for a category), NULL is returned.
 * @param[in] config The configuration instance
 * @returns A pointer to a valid janus_config_container instance if successful, NULL otherwise */
janus_config_container *janus_config_search(janus_config *config, ...);

/*! \brief Add an item/category/array instance to a category or array
 * \note If adding to a category and the item/category/array already exists, it is replaced;
 * it is appended if the target is an array instead, where duplicates are accepted.
 * @param[in] config The configuration instance
 * @param[in] parent The category or array to add the item to, if any
 * @param[in] item The item/category/array to add
 * @returns 0 if successful, a negative integer otherwise */
int janus_config_add(janus_config *config, janus_config_container *parent, janus_config_container *item);
/*! \brief Remove an existing item with the specific name from a category/array
 * @param[in] config The configuration instance
 * @param[in] parent The category/array to remove the item from, if any
 * @param[in] name The name of the item/category/array to remove
 * @returns 0 if successful, a negative integer otherwise */
int janus_config_remove(janus_config *config, janus_config_container *parent, const char *name);

/*! \brief Helper method to return the list of plain items, either in root or from a parent
 * @note The method returns a new GList: it's up to the caller to free it. The values
 * of the list data must NOT be freed, though, as it's just linked from the configuration.
 * @param[in] config The configuration instance
 * @param[in] parent The parent container (category or array), if any
 * @returns A pointer to the categories GLib linked list of items if successful, NULL otherwise */
GList *janus_config_get_items(janus_config *config, janus_config_container *parent);
/*! \brief Helper method to return the list of categories, either in root or from a parent
 * @note The method returns a new GList: it's up to the caller to free it. The values
 * of the list data must NOT be freed, though, as it's just linked from the configuration.
 * @param[in] config The configuration instance
 * @param[in] parent The parent container (category or array), if any
 * @returns A pointer to the categories GLib linked list of categories if successful, NULL otherwise */
GList *janus_config_get_categories(janus_config *config, janus_config_container *parent);
/*! \brief Helper method to return the list of arrays, either in root or from a parent
 * @note The method returns a new GList: it's up to the caller to free it. The values
 * of the list data must NOT be freed, though, as it's just linked from the configuration.
 * @param[in] config The configuration instance
 * @param[in] parent The parent container (category or array), if any
 * @returns A pointer to the categories GLib linked list of arrays if successful, NULL otherwise */
GList *janus_config_get_arrays(janus_config *config, janus_config_container *parent);

#endif

/*! \file    config.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Configuration files parsing (headers)
 * \details  Implementation of a parser of INI and YAML configuration files.
 * 
 * \ingroup core
 * \ref core
 */

#ifndef _JANUS_CONFIG_H
#define _JANUS_CONFIG_H

#include <glib.h>

/*! \brief Configuration item */
typedef struct janus_config_item {
	/*! \brief Whether this is a category, or an item */
	gboolean category;
	/*! \brief Name of the item/category */
	const char *name;
	/*! \brief Value of the item (item only) */
	const char *value;
	/*! \brief Linked list of items (category only) */
	GList *items;
	/*! \brief Linked list of subcategories (category only)
	 * \note Currently unused, will be useful in the future */
	GList *subcategories;
} janus_config_item;

/*! \brief Configuration category (defined for backwards compatibility) */
typedef struct janus_config_item janus_config_category;

/*! \brief Configuration container */
typedef struct janus_config {
	/*! \brief Whether this is a YAML or an INI config */
	gboolean is_yaml;
	/*! \brief Name of the configuration */
	const char *name;
	/*! \brief Linked list of uncategorized items */
	GList *items;
	/*! \brief Linked list of categories category */
	GList *categories;
} janus_config;


/*! \brief Method to parse an INI configuration file
 * @param[in] config_file Path to the configuration file
 * @returns A pointer to a valid janus_config instance if successful, NULL otherwise */
janus_config *janus_config_parse(const char *config_file);
/*! \brief Method to create a new, empty, configuration
 * @param[in] name Name to give to the configuration
 * @returns A pointer to a valid janus_config instance if successful, NULL otherwise */
janus_config *janus_config_create(const char *name);
/*! \brief Get the list of all subcategories, either from the root or a specific parent category
 * @param[in] config The configuration container
 * @param[in] parent The parent category, if any
 * @returns A pointer to the subcategories GLib linked list if successful, NULL otherwise */
GList *janus_config_get_categories(janus_config *config, janus_config_category *parent);
/*! \brief Get the subcategory with a specific name by crawling the parent categories from a parsed configuration
 * @param[in] config The configuration container
 * @returns A pointer to the janus_config_category instance if successful, NULL otherwise */
janus_config_category *janus_config_get_category(janus_config *config, ...);
/*! \brief Get the list of all items in a category as a GLib linked list
 * @param[in] category The configuration category
 * @returns A pointer to the items GLib linked list if successful, NULL otherwise */
GList *janus_config_get_items(janus_config_category *category);
/*! \brief Get the item with a specific name from a category of a parsed configuration
 * @param[in] category The configuration category
 * @param[in] name The name of the item
 * @returns A pointer to the janus_config_item instance if successful, NULL otherwise */
janus_config_item *janus_config_get_item(janus_config_category *category, const char *name);
/*! \brief Add a new category, optionally to a parent category if specified
 * \note Passing a NULL category means adding the category to the root of the configuration instead. If the category
 * already exists in the parent or root, it is NOT overwritten, and the existing instance is returned
 * @param[in] config The configuration container
 * @param[in] parent The parent category to add the new category to, if any
 * @param[in] category The category to create
 * @returns A pointer to the janus_config_category instance if successful, NULL otherwise */
janus_config_category *janus_config_add_category(janus_config *config, janus_config_category *parent, const char *category);
/*! \brief Remove an existing category with the specific name from either root or a parent category
 * \note This will also remove all items from that bcategory. In case the
 * parent category is NULL, this removes the category from the root
 * @param[in] config The configuration container
 * @param[in] parent The parent category to remove the category from, if any
 * @param[in] category The category to remove
 * @returns 0 if successful, a negative integer otherwise */
int janus_config_remove_category(janus_config *config, janus_config_category *parent, const char *category);
/*! \brief Add a new item with the specific name and value to a category, and create the category if it doesn't exist
 * \note If the item already exists in the category, its value is overwritten
 * @param[in] config The configuration container
 * @param[in] category The category to add the item to, and to create if it doesn't exist
 * @param[in] name The name of the item
 * @param[in] value The value of the item
 * @returns A pointer to the janus_config_item instance if successful, NULL otherwise */
janus_config_item *janus_config_add_item(janus_config *config, janus_config_category *category, const char *name, const char *value);
/*! \brief Remove an existing item with the specific name from a category
 * @param[in] config The configuration container
 * @param[in] category The category to remove the item from
 * @param[in] name The name of the item
 * @returns 0 if successful, a negative integer otherwise */
int janus_config_remove_item(janus_config *config, janus_config_category *category, const char *name);
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
 * @param[in] filename The file name, extension included (should be .cfg)
 * @returns 0 if successful, a negative integer otherwise */
int janus_config_save(janus_config *config, const char *folder, const char *filename);
/*! \brief Destroy a configuration container instance
 * @param[in] config The configuration to destroy */
void janus_config_destroy(janus_config *config);


#endif

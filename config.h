/*! \file    config.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Configuration files parsing (headers)
 * \details  Implementation of a parser of INI configuration files (based on libini-config).
 * 
 * \ingroup core
 * \ref core
 */

#ifndef _JANUS_CONFIG_H
#define _JANUS_CONFIG_H

#include <ini_config.h>


/*! \brief Configuration item (name=value) */
typedef struct janus_config_item {
	/*! \brief Name of the item */
	const char *name;
	/*! \brief Value of the item */
	const char *value;
	/*! \brief Next element in the linked list of items in this category */
	struct janus_config_item *next;
} janus_config_item;

/*! \brief Configuration category ([category]) */
typedef struct janus_config_category {
	/*! \brief Name of the category */
	const char *name;
	/*! \brief Linked list of items */
	janus_config_item *items;
	/*! \brief Next element in the linked list of categories in this configuration */
	struct janus_config_category *next;
} janus_config_category;

/*! \brief Configuration container */
typedef struct janus_config {
	/*! \brief Name of the configuration */
	const char *name;
	/*! \brief Linked list of uncategorized items */
	janus_config_item *items;
	/*! \brief Linked list of categories category */
	janus_config_category *categories;
} janus_config;


/*! \brief Method to parse an INI configuration file
 * @param[in] config_file Path to the configuration file
 * @returns A pointer to a valid janus_config instance if successful, NULL otherwise */ 
janus_config *janus_config_parse(const char *config_file);
/*! \brief Method to create a new, empty, configuration
 * @param[in] name Name to give to the configuration
 * @returns A pointer to a valid janus_config instance if successful, NULL otherwise */ 
janus_config *janus_config_create(const char *name);
/*! \brief Get all categories from a parsed configuration
 * @param[in] config The configuration container
 * @returns A pointer to the first janus_config_category instance in the list if successful, NULL otherwise */ 
janus_config_category *janus_config_get_categories(janus_config *config);
/*! \brief Get the category with a specific name from a parsed configuration
 * @param[in] config The configuration container
 * @param[in] name The name of the category
 * @returns A pointer to the janus_config_category instance if successful, NULL otherwise */ 
janus_config_category *janus_config_get_category(janus_config *config, const char *name);
/*! \brief Get all items from a category of a parsed configuration
 * @param[in] category The configuration category
 * @returns A pointer to the first janus_config_item instance in the list if successful, NULL otherwise */ 
janus_config_item *janus_config_get_items(janus_config_category *category);
/*! \brief Get the item with a specific name from a category of a parsed configuration
 * @param[in] category The configuration category
 * @param[in] name The name of the item
 * @returns A pointer to the janus_config_item instance if successful, NULL otherwise */ 
janus_config_item *janus_config_get_item(janus_config_category *category, const char *name);
/*! \brief Get the item with a specific name from a category with a specific name from a parsed configuration
 * \note This is the same as janus_config_get_item, but it looks for the janus_config_category for you
 * @param[in] config The configuration container
 * @param[in] category The name of the configuration category
 * @param[in] name The name of the item
 * @returns A pointer to the janus_config_item instance if successful, NULL otherwise */ 
janus_config_item *janus_config_get_item_drilldown(janus_config *config, const char *category, const char *name);
/*! \brief Add a new item with the specific name and value to a category, and create the category if it doesn't exist
 * \note If the item already exists in the category, its value is overwritten
 * @param[in] config The configuration container
 * @param[in] category The category to add the item to, and to create if it doesn't exist
 * @param[in] name The name of the item
 * @param[in] value The value of the item
 * @returns A pointer to the janus_config_item instance if successful, NULL otherwise */ 
janus_config_item *janus_config_add_item(janus_config *config, const char *category, const char *name, const char *value);
/*! \brief Helper method to print a configuration on the standard output
 * @param[in] config The configuration to print */
void janus_config_print(janus_config *config);
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

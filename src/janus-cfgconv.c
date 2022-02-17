/*! \file    janus-cfgconv.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Simple utility to convert Janus .cfg files to .jcfg and viceversa
 * \details  Historically, Janus has made use of INI .cfg files for the
 * configuration of core and plugins. Recently, support for the libconfig format
 * has been added too. Due to the more expressive nature of libconfig, .jcfg
 * files have been made the default: while support for .cfg files still
 * exists as a fallback, new features may only be available in .jcfg files.
 * As such, you may want to convert your existing .cfg configuration files
 * to .jcfg as soon as possible, which is what this tool allows you to do.
 * Notice that the tool also allows you to go the other way around, although
 * libconfig concepts that cannot be expressed in INI will be lost in the process.
 *
 * Using the utility is quite simple. Just pass, as arguments to the tool,
 * the path to the file you want to convert (.cfg or .jcfg) and the path to
 * the target file (.jcfg or .cfg), e.g.:
 *
\verbatim
./janus-cfgconv /path/to/config.cfg /path/to/config.jcfg
\endverbatim
 *
 * \ingroup tools
 * \ref tools
 */

#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "debug.h"
#include "version.h"

int janus_log_level = 4;
gboolean janus_log_timestamps = FALSE;
gboolean janus_log_colors = TRUE;
char *janus_log_global_prefix = NULL;
int lock_debug = 0;

/* Main Code */
int main(int argc, char *argv[])
{
	janus_log_init(FALSE, TRUE, NULL);
	atexit(janus_log_destroy);

	JANUS_LOG(LOG_INFO, "Janus version: %d (%s)\n", janus_version, janus_version_string);
	JANUS_LOG(LOG_INFO, "Janus commit: %s\n", janus_build_git_sha);
	JANUS_LOG(LOG_INFO, "Compiled on:  %s\n\n", janus_build_git_time);

	/* Evaluate arguments */
	if(argc != 3) {
		JANUS_LOG(LOG_INFO, "Usage: %s source.[cfg|jcfg] destination.[cfg|jcfg]\n", argv[0]);
		JANUS_LOG(LOG_INFO, "       %s --parse source.[cfg|jcfg]\n", argv[0]);
		exit(1);
	}
	char *source = NULL, *destination = NULL;
	/* Parse or convert the configuration files */
	gboolean only_parse = FALSE;
	source = argv[1];
	if(!strcmp(source, "--parse")) {
		only_parse = TRUE;
	} else {
		if(!strstr(source, ".cfg") && !strstr(source, ".jcfg")) {
			JANUS_LOG(LOG_ERR, "Unsupported file: %s\n", source);
			exit(1);
		}
	}
	destination = argv[2];
	if(!strstr(destination, ".cfg") && !strstr(destination, ".jcfg")) {
		JANUS_LOG(LOG_ERR, "Unsupported file: %s\n", destination);
		exit(1);
	}
	if(only_parse) {
		source = destination;
		destination = NULL;
		JANUS_LOG(LOG_INFO, "Parsing:\n");
		JANUS_LOG(LOG_INFO, "   -- IN:  %s\n", source);
	} else {
		JANUS_LOG(LOG_INFO, "Converting:\n");
		JANUS_LOG(LOG_INFO, "   -- IN:  %s\n", source);
		JANUS_LOG(LOG_INFO, "   -- OUT: %s\n\n", destination);
	}
	/* Open the source */
	janus_config *config = janus_config_parse(source);
	if(config == NULL)
		exit(1);
	janus_config_print_as(config, LOG_INFO);
	JANUS_LOG(LOG_INFO, "\n");
	if(only_parse) {
		/* We're done */
		janus_config_destroy(config);
		JANUS_LOG(LOG_INFO, "Bye!\n");
		return 0;
	}
	/* If the source is an INI, check if there are numeric categories or attribute names */
	if(!config->is_jcfg) {
		GList *list = config->list;
		while(list) {
			janus_config_container *c = (janus_config_container *)list->data;
			if(c && c->type == janus_config_type_category && c->name && atol(c->name) > 0) {
				/* FIXME Ugly hack to add the "room-" prefix to category names
				 * (currently only needed in VideoRoom/AudioBridge/TextRoom) */
				char newname[50];
				g_snprintf(newname, sizeof(newname), "room-%s", c->name);
				g_free((char *)c->name);
				c->name = g_strdup(newname);
			}
			list = list->next;
		}
	}
	/* Is the target an INI or a libconfig file? */
	config->is_jcfg = strstr(destination, ".jcfg") != NULL;
	/* Remove extension: janus_config_save adds it for us */
	char *target = g_strdup(destination);
	char *extension = config->is_jcfg ? strstr(target, ".jcfg") : strstr(target, ".cfg");
	*extension = '\0';
	/* Save to destination */
	if(janus_config_save(config, NULL, target) < 0) {
		g_free(target);
		janus_config_destroy(config);
		JANUS_LOG(LOG_ERR, "Error saving converted file\n");
		exit(1);
	}
	janus_config_destroy(config);
	/* Make sure everything's fine */
	config = janus_config_parse(destination);
	if(config == NULL) {
		g_free(target);
		JANUS_LOG(LOG_ERR, "Error parsing converted file\n");
		exit(1);
	}
	janus_config_print_as(config, LOG_INFO);
	JANUS_LOG(LOG_INFO, "\n");
	janus_config_destroy(config);
	/* Done */
	FILE *file = fopen(destination, "rb");
	if(file == NULL) {
		g_free(target);
		JANUS_LOG(LOG_WARN, "No destination file %s??\n", destination);
		exit(1);
	}
	fseek(file, 0L, SEEK_END);
	size_t fsize = ftell(file);
	fseek(file, 0L, SEEK_SET);
	JANUS_LOG(LOG_INFO, "%s is %zu bytes\n", destination, fsize);
	fclose(file);
	g_free(target);

	JANUS_LOG(LOG_INFO, "Bye!\n");
	return 0;
}

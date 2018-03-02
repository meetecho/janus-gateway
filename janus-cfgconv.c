/*! \file    janus-cfgconv.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Simple utility to convert Janus .cfg files to .yaml and viceversa
 * \details  Historically, Janus has made use of INI .cfg files for the
 * configuration of core and plugins. Recently, support for .yaml files
 * has been added too. Due to the more expressive nature of YAML, .yaml
 * files have been made the default: while support for .cfg files still
 * exists as a fallback, new features may only be available in .yaml files.
 * As such, you may want to convert your existing .cfg configuration files
 * to .yaml as soon as possible, which is what this tool allows you to do.
 * Notice that the tool also allows you to go the other way around, although
 * YAML concepts that cannot be expressed in INI will be lost in the process.
 * 
 * Using the utility is quite simple. Just pass, as arguments to the tool,
 * the path to the file you want to convert (.cfg or .yaml) and the path to
 * the target file (.yaml or .cfg), e.g.:
 * 
\verbatim
./janus-cfgconv /path/to/config.cfg /path/to/config.yaml
\endverbatim 
 * 
 * \ingroup utilities
 * \ref utilities
 */

#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "debug.h"
#include "version.h"

int janus_log_level = 4;
gboolean janus_log_timestamps = FALSE;
gboolean janus_log_colors = TRUE;

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
		JANUS_LOG(LOG_INFO, "Usage: %s source.[cfg|yaml] destination.[cfg|yaml]\n", argv[0]);
		exit(1);
	}
	char *source = NULL, *destination = NULL;
	/* Convert the configuration files */
	source = argv[1];
	if(!strstr(source, ".cfg") && !strstr(source, ".yaml")) {
		JANUS_LOG(LOG_ERR, "Unsupported file: %s\n", source);
		exit(1);
	}
	destination = argv[2];
	if(!strstr(destination, ".cfg") && !strstr(destination, ".yaml")) {
		JANUS_LOG(LOG_ERR, "Unsupported file: %s\n", destination);
		exit(1);
	}
	JANUS_LOG(LOG_INFO, "Converting:\n");
	JANUS_LOG(LOG_INFO, "   -- IN:  %s\n", source);
	JANUS_LOG(LOG_INFO, "   -- OUT: %s\n\n", destination);
	/* Open the source */
	janus_config *config = janus_config_parse(source);
	if(config == NULL)
		exit(1);
	janus_config_print_as(config, LOG_INFO);
	JANUS_LOG(LOG_INFO, "\n");
	/* Is the target an INI or a YAML file? */
	config->is_yaml = strstr(destination, ".yaml") != NULL;
	/* Remove extension: janus_config_save adds it for us */
	char *target = g_strdup(destination);
	char *extension = config->is_yaml ? strstr(target, ".yaml") : strstr(target, ".cfg");
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

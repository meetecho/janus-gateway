/*! \file   version.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus GitHub versioning (headers)
 * \details This exposes a quick an easy way to display the commit the
 * compiled version of Janus implements, and when it has been built. It
 * is based on this excellent comment: http://stackoverflow.com/a/1843783
 *
 * \ingroup core
 * \ref core
 */

#ifndef JANUS_VERSION_H
#define JANUS_VERSION_H

extern int janus_version;
extern const char *janus_version_string;
extern const char *janus_build_git_time;
extern const char *janus_build_git_sha;

/* Dependencies (those we can't get programmatically) */
extern const char *libnice_version_string;

#endif

/*! \file    ip-utils.c
 *\author   Johan Ouwerkerk <jm.ouwerkerk@gmail.com>
 *\copyright GNU General Public License v3
 *\brief    IP address related utility functions
 *\details  Provides functions to query for network devices with a given device name or address.
 *Devices may be looked up by either a device name or by the IPv4 or IPv6 address of the configured network interface.
 *This functionality may be used to bind to user configurable network devices instead of relying on unpredictable implementation defined defaults.
 *Parsing IPv4/IPv6 addresses is done using inet_pton(), making these functions generally robust against malformed input.
 *
 *\ingroup core
 *\ref core
 */

#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <string.h>
#include <unistd.h>

#include <glib.h>

#include "ip-utils.h"

static int janus_ip_compare_byte_arrays(const uint8_t *b1, const uint8_t *b2, const size_t size) {
	size_t i;
	for(i = 0; i < size; ++i) {
		if(b1[i] != b2[i]) {
			return b1[i] > b2[i] ? 1 : -1;
		}
	}
	return 0;
}

static int janus_ip_iface_matches_name(const struct ifaddrs *ifa, const char *name) {
	return ifa->ifa_addr && (ifa->ifa_addr->sa_family == AF_INET || ifa->ifa_addr->sa_family == AF_INET6)
		&& name && ifa->ifa_name && strncmp(ifa->ifa_name, name, IFNAMSIZ) == 0 ? 1 : 0;
}

static int janus_ip_iface_matches_ipv4(const struct ifaddrs *ifa, const struct in_addr *ipv4) {
	if(ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
		struct sockaddr_in *iface = (struct sockaddr_in *) ifa->ifa_addr;
		if(iface->sin_addr.s_addr == ipv4->s_addr) {
			return 1;
		}
	}
	return 0;
}

static int janus_ip_iface_matches_ipv6(const struct ifaddrs *ifa, const struct in6_addr *ipv6) {
	if(ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *iface = (struct sockaddr_in6 *) ifa->ifa_addr;
		if(janus_ip_compare_byte_arrays(iface->sin6_addr.s6_addr, ipv6->s6_addr, 16) == 0) {
			return 1;
		}
	}
	return 0;
}

static int janus_ip_iface_matches(const struct ifaddrs *ifa, const janus_network_query_config *query) {
	if(ifa && query) {
		return
			((query->mode & janus_network_query_options_ipv4) && janus_ip_iface_matches_ipv4(ifa, &query->ipv4) == 1) ||
			((query->mode & janus_network_query_options_ipv6) && janus_ip_iface_matches_ipv6(ifa, &query->ipv6) == 1) ||
			((query->mode & janus_network_query_options_name) && janus_ip_iface_matches_name(ifa, query->device_name) == 1) ? 1 : 0;
	} else {
		return -EINVAL;
	}
}

const struct ifaddrs *janus_network_query_devices(const struct ifaddrs *ifa, const janus_network_query_config *query) {
	while(ifa) {
		if(janus_ip_iface_matches(ifa, query) == 1) {
			return ifa;
		}
		ifa = ifa->ifa_next;
	}
	return NULL;
}

int janus_network_prepare_device_query(const char *user_value, const janus_network_query_options query_mode, janus_network_query_config *query) {
	if(user_value && query) {
		query->mode = janus_network_query_options_none;

		if((query_mode & janus_network_query_options_ipv4) && inet_pton(AF_INET, user_value, &query->ipv4) > 0) {
			query->mode |= janus_network_query_options_ipv4;
		}

		if((query_mode & janus_network_query_options_ipv6) && inet_pton(AF_INET6, user_value, &query->ipv6) > 0) {
			query->mode |= janus_network_query_options_ipv6;
		}

		if(query_mode & janus_network_query_options_name) {
			query->device_name = user_value;
			query->mode |= janus_network_query_options_name;
		}

		return ((query_mode == janus_network_query_options_none) == (query->mode == janus_network_query_options_none)) ? 0 : -EINVAL;
	} else {
		return -EINVAL;
	}
}

int janus_network_prepare_device_query_default(const char *user_value, janus_network_query_config *query) {
	return janus_network_prepare_device_query(user_value, janus_network_query_options_any, query);
}

static int janus_ip_copy_ipv4(const struct sockaddr_in *iface, struct in_addr *result) {
	result->s_addr = iface->sin_addr.s_addr;
	return 0;
}

int janus_network_get_devices_ipv4(const struct ifaddrs *ifa, const janus_network_query_config *query, struct in_addr *result) {
	if(ifa && ifa->ifa_addr && (ifa->ifa_addr->sa_family == AF_INET) && result && query && (query->mode & janus_network_query_options_ipv4)) {
		return janus_ip_copy_ipv4((struct sockaddr_in *) ifa->ifa_addr, result);
	} else {
		return -EINVAL;
	}
}

static int janus_ip_copy_ipv6(const struct sockaddr_in6 *iface, struct in6_addr *result) {
	size_t i;
	const uint8_t *src = iface->sin6_addr.s6_addr;
	uint8_t *dst = result->s6_addr;
	for(i = 0; i < 16; ++i) {
		dst[i] = src[i];
	}
	return 0;
}

int janus_network_get_devices_ipv6(const struct ifaddrs *ifa, const janus_network_query_config *query, struct in6_addr *result) {
	if(ifa && ifa->ifa_addr && (ifa->ifa_addr->sa_family == AF_INET6) && result && query && (query->mode & janus_network_query_options_ipv6)) {
		return janus_ip_copy_ipv6((struct sockaddr_in6 *) ifa->ifa_addr, result);
	} else {
		return -EINVAL;
	}
}

int janus_network_get_device_address(const struct ifaddrs *ifa, janus_network_address *result) {
	if(ifa && ifa->ifa_addr && result) {
		switch(ifa->ifa_addr->sa_family) {
			case AF_INET:
				result->family = AF_INET;
				return janus_ip_copy_ipv4((struct sockaddr_in *) ifa->ifa_addr, &result->ipv4);
			case AF_INET6:
				result->family = AF_INET6;
				return janus_ip_copy_ipv6((struct sockaddr_in6 *) ifa->ifa_addr, &result->ipv6);
			default:
				return -EINVAL;
		}
	} else {
		return -EINVAL;
	}
}

void janus_network_address_nullify(janus_network_address *a) {
	if(a) {
		memset(a, '\0', sizeof(janus_network_address));
		a->family = AF_UNSPEC;
	}
}

int janus_network_address_is_null(const janus_network_address *a) {
	return !a || a->family == AF_UNSPEC;
}

int janus_network_address_from_sockaddr(struct sockaddr *s, janus_network_address *a) {
	if(!s || !a)
		return -EINVAL;
	if(s->sa_family == AF_INET) {
		a->family = AF_INET;
		struct sockaddr_in *addr = (struct sockaddr_in *)s;
		a->ipv4 = addr->sin_addr;
		return 0;
	} else if(s->sa_family == AF_INET6) {
		a->family = AF_INET6;
		struct sockaddr_in6 *addr = (struct sockaddr_in6 *)s;
		a->ipv6 = addr->sin6_addr;
		return 0;
	}
	return -EINVAL;
}

int janus_network_address_to_string_buffer(const janus_network_address *a, janus_network_address_string_buffer *buf) {
	if(buf && !janus_network_address_is_null(a)) {
		janus_network_address_string_buffer_nullify(buf);
		buf->family = a->family;
		if(a->family == AF_INET) {
			return inet_ntop(AF_INET, &a->ipv4, buf->ipv4, INET_ADDRSTRLEN) ? 0 : -errno;
		} else {
			return inet_ntop(AF_INET6, &a->ipv6, buf->ipv6, INET6_ADDRSTRLEN) ? 0 : -errno;
		}
	} else {
		return -EINVAL;
	}
}

void janus_network_address_string_buffer_nullify(janus_network_address_string_buffer *b) {
	if(b) {
		memset(b, '\0', sizeof(janus_network_address_string_buffer));
		b->family = AF_UNSPEC;
	}
}

int janus_network_address_string_buffer_is_null(const janus_network_address_string_buffer *b) {
	return !b || b->family == AF_UNSPEC;
}

const char *janus_network_address_string_from_buffer(const janus_network_address_string_buffer *b) {
	if(janus_network_address_string_buffer_is_null(b)) {
		return NULL;
	} else {
		return b->family == AF_INET ? b->ipv4 : b->ipv6;
	}
}

int janus_network_string_is_valid_address(janus_network_query_options addr_type, const char *user_value) {
	janus_network_address a;
	return janus_network_string_to_address(addr_type, user_value, &a) == 0;
}

int janus_network_string_to_address(janus_network_query_options addr_type, const char *user_value, janus_network_address *result) {
	if((addr_type != janus_network_query_options_ipv4 &&
			addr_type != janus_network_query_options_ipv6 &&
			addr_type != janus_network_query_options_any_ip) || !user_value || !result) {
		return -EINVAL;
	}
	if((addr_type & janus_network_query_options_ipv4) && inet_pton(AF_INET, user_value, &result->ipv4) > 0) {
		result->family = AF_INET;
		return 0;
	}
	if((addr_type & janus_network_query_options_ipv6) && inet_pton(AF_INET6, user_value, &result->ipv6) > 0) {
		result->family = AF_INET6;
		return 0;
	}
	return -EINVAL;
}

int janus_network_lookup_interface(const struct ifaddrs *ifas, const char *iface, janus_network_address *result) {
	if(ifas == NULL || iface == NULL || result == NULL)
		return -EINVAL;
	janus_network_address_nullify(result);
	janus_network_query_config q;
	/* Let's see if iface is an IPv4 address, an IPv6 address, or possibly an interface name */
	int res = janus_network_prepare_device_query(iface,
			janus_network_query_options_ipv4 | janus_network_query_options_ipv6 | janus_network_query_options_name, &q);
	if(res != 0) {
		/* None of them..? */
		return res;
	}
	const struct ifaddrs *found = janus_network_query_devices(ifas, &q);
	if(!found || janus_network_get_device_address(found, result)) {
		/* Couldn't find anything on iface */
		return -EINVAL;
	}
	/* Done */
	return 0;
}

int janus_network_detect_local_ip(janus_network_query_options addr_type, janus_network_address *result) {
	if(result == NULL)
		return -EINVAL;
	janus_network_address_nullify(result);
	gboolean found = FALSE;
	int fd = -1;
	if(addr_type == janus_network_query_options_ipv4 || addr_type == janus_network_query_options_any_ip) {
		/* Let's try IPv4 (FIXME Should probably use other internal methods) */
		struct sockaddr_in addr;
		socklen_t len;
		fd = socket(AF_INET, SOCK_DGRAM, 0);
		if(fd > -1) {
			addr.sin_family = AF_INET;
			addr.sin_port = htons(1);
			inet_pton(AF_INET, "1.2.3.4", &addr.sin_addr);
			if(connect(fd, (const struct sockaddr*)&addr, sizeof(addr)) > -1) {
				len = sizeof(addr);
				if(getsockname(fd, (struct sockaddr*)&addr, &len) > -1) {
					result->family = AF_INET;
					if(janus_ip_copy_ipv4((struct sockaddr_in *)&addr, &result->ipv4) == 0) {
						found = TRUE;
					}
				}
			}
		}
	}
	if(fd != -1)
		close(fd);
	fd = -1;
	if(!found && (addr_type == janus_network_query_options_ipv6 || addr_type == janus_network_query_options_any_ip)) {
		/* Let's try IPv6 (FIXME Should probably use other internal methods) */
		struct sockaddr_in6 addr;
		socklen_t len;
		fd = socket(AF_INET6, SOCK_DGRAM, 0);
		if(fd > -1) {
			addr.sin6_family = AF_INET6;
			addr.sin6_port = htons(1);
			inet_pton(AF_INET6, "::1.2.3.4", &addr.sin6_addr);
			if(connect(fd, (const struct sockaddr*)&addr, sizeof(addr)) > -1) {
				len = sizeof(addr);
				if(getsockname(fd, (struct sockaddr*)&addr, &len) > -1) {
					result->family = AF_INET6;
					if(janus_ip_copy_ipv6((struct sockaddr_in6 *)&addr, &result->ipv6) == 0) {
						found = TRUE;
					}
				}
			}
		}
	}
	if(fd != -1)
		close(fd);
	return found ? 0 : -EINVAL;
}

char *janus_network_detect_local_ip_as_string(janus_network_query_options addr_type) {
	janus_network_address addr;
	janus_network_address_string_buffer buf;
	int res = janus_network_detect_local_ip(addr_type, &addr) || janus_network_address_to_string_buffer(&addr, &buf);
	if(res != 0)
		return NULL;
	return g_strdup(janus_network_address_string_from_buffer(&buf));
}

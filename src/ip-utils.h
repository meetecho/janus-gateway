/*! \file    ip-utils.h
 * \author   Johan Ouwerkerk <jm.ouwerkerk@gmail.com>
 * \copyright GNU General Public License v3
 * \brief    IP address related utility functions (headers)
 * \details  Provides functions to query for network devices with a given device name or address.
 * Devices may be looked up by either a device name or by the IPv4 or IPv6 address of the configured network interface.
 * This functionality may be used to bind to user configurable network devices instead of relying on unpredictable implementation defined defaults.
 *
 * Parsing IPv4/IPv6 addresses is robust against malformed input.
 *
 * \see man 3 getifaddrs
 * \see man 3 inet_pton
 * \ingroup core
 * \ref core
 */

#ifndef JANUS_IP_UTILS_H
#define JANUS_IP_UTILS_H

#include <ifaddrs.h>
#include <netinet/in.h>


/** @name Janus helper methods to match names and addresses with network interfaces/devices.
 */
///@{
typedef enum janus_network_query_options {
	janus_network_query_options_none = 0,
	janus_network_query_options_name = 1,
	janus_network_query_options_ipv4 = 2,
	janus_network_query_options_ipv6 = 4,
	janus_network_query_options_any_ip = 6,
	janus_network_query_options_any = 7
} janus_network_query_options;

/*!
 * \brief Internal object representation of a network device query (configuration).
 */
typedef struct janus_network_query_config {
	const char *device_name;
	janus_network_query_options mode;
	struct in_addr ipv4;
	struct in6_addr ipv6;
} janus_network_query_config;

/*!
 * \brief Structure to hold network addresses in a tagged union which should be IPv4 and IPv6 compatible.
 * Use the \c family member (either \c AF_INET or \c AF_INET6) to determine which type of address is contained.
 * \see man 7 ip
 * \see man 7 ipv6
 * \see \c janus_network_get_device_address
 */
typedef struct janus_network_address {
	/*!
	 * Should be either \c AF_INET for IPv4 or \c AF_INET6 for IPv6.
	 */
	int family;
	union {
		struct in_addr ipv4;
		struct in6_addr ipv6;
	};
} janus_network_address;

/*!
 * \brief Structure to hold human readable forms of network addresses in a tagged union which should be IPv4 and IPv6 compatible.
 * Use the \c family member (either \c AF_INET or \c AF_INET6) to determine which type of representation is contained.
 * \see man 7 ip
 * \see man 7 ipv6
 * \see \c janus_network_address_to_string_buffer
 */
typedef struct janus_network_address_string_buffer {
	/*!
	 * Should be either \c AF_INET for IPv4 or \c AF_INET6 for IPv6.
	 */
	int family;
	union {
		char ipv4[INET_ADDRSTRLEN];
		char ipv6[INET6_ADDRSTRLEN];
	};
} janus_network_address_string_buffer;

/*!
 * \brief Initialise a network device query.
 * \param user_value The user-supplied string which is supposed to describe either the device name or its IP address.
 * \param query_mode (A mask of) Options describing the supported types of matches which should be accepted when performing a look up with this query.
 * This can be used to restrict the query to 'by device name' or 'IPv4 only' type searches.
 * \param query The query object to configure.
 * \return 0 on success or -EINVAL if any of the arguments are NULL or the given value to look for does not correspond to a valid IPv4/IPv6 address and
 * matching by name is disabled.
 * \see \c janus_network_query_options
 */
int janus_network_prepare_device_query(const char *user_value, const janus_network_query_options query_mode, janus_network_query_config *query);

/*!
 * \brief Initialise a network device query with default query options.
 * \p This function will Initialise the query to accept any supported match type.
 * \param user_value The user-supplied string which is supposed to describe either the device name or its IP address.
 * \param query The query object to configure.
 * \return 0 on success, or -EINVAL if any of the arguments are NULL
 * \see \c janus_network_prepare_device_query
 */
int janus_network_prepare_device_query_default(const char *user_value, janus_network_query_config *query);

/*!
 * \brief Look up network devices matching the given query.
 * The first matching device is returned, so to find all matching devices
 * simply pass the `ifa_next` of the returned device in a subsequent call to this function to find more matches.
 * \param ifas The first node of the list of network interfaces to search through. This should be obtained (indirectly) from
 * \c getifaddrs().
 * \param query A description of the criteria to look for when determining whether or not a network interface is a match.
 * \return a pointer to a node describing the matching network interface or `NULL` if no (further) match was found.
 * \see man 3 getifaddrs
 */
const struct ifaddrs *janus_network_query_devices(const struct ifaddrs *ifas, const janus_network_query_config *query);

/*!
 * \brief Copies the IPv4 address from a network inteface description to the given result structure.
 * \param ifa The network interface description to grab the IPv4 address from. It should be obtained with `janus_network_query_devices()`.
 * \param query A description of the criteria to look for when determining whether or not a network interface is a match
 * \param result Pointer to a structure to populate with the IPv4 address of the given network interface
 * \return 0 on success, -EINVAL if any argument is NULL or the network interface description or the network device query do not correspond to an IPv4 configuration.
 * \see man 7 ip
 * \see \c janus_network_query_devices
 */
int janus_network_get_devices_ipv4(const struct ifaddrs *ifa, const janus_network_query_config *query, struct in_addr *result);

/*!
 * \brief Copies the IPv6 address from a network inteface description to the given result structure.
 * \param ifa The network interface description to grab the IPv6 address from. It should be obtained with `janus_network_query_devices()`.
 * \param query A description of the criteria to look for when determining whether or not a network interface is a match
 * \param result Pointer to a structure to populate with the IPv6 address of the given network interface
 * \return 0 on success, -EINVAL if any argument is NULL or the network interface description or the network device query do not correspond to an IPv6 configuration.
 * \see man 7 ipv6
 * \see \c janus_network_query_devices
 */
int janus_network_get_devices_ipv6(const struct ifaddrs *ifa, const janus_network_query_config *query, struct in6_addr *result);

/*!
 * \brief Copies the IP address from a network interface description to the given result structure.
 * \return 0 on success, or -EINVAL if any argument is NULL or the given network interface does not correspond to an IP address.
 * \see \c janus_network_address
 */
int janus_network_get_device_address(const struct ifaddrs *ifa, janus_network_address *result);

/*!
 * \brief Set the given network address to a null/nil value.
 * \param a The address to nullify. Nothing is done if the pointer is NULL itself.
 * \see \c janus_network_address_is_null
 */
void janus_network_address_nullify(janus_network_address *a);

/*!
 * \brief Test if a given network address is null-valued
 * \param a The address to check
 * \return A positive integer if the given address is null-valued, 0 otherwise.
 * \see \c janus_network_address_nullify
 */
int janus_network_address_is_null(const janus_network_address *a);

/*!
 * \brief Convert a struct sockaddr to a janus_network_address
 * \param s The struct sockaddr to convert
 * \param a The address to write to
 * \return 0 on success, or -EINVAL otherwise.
 */
int janus_network_address_from_sockaddr(struct sockaddr *s, janus_network_address *a);

/*!
 * \brief Convert the given network address to a form which can be used to extract a human readable network address from.
 * \param a The address to convert
 * \param buf A buffer to contain the human readable form.
 * \return 0 on success, or -EINVAL if any argument is NULL.
 * \see \c janus_network_address
 * \see \c janus_network_address_string_buffer
 * \see \c janus_network_address_string_from_buffer
 * \see man 3 inet_ntop
 */
int janus_network_address_to_string_buffer(const janus_network_address *a, janus_network_address_string_buffer *buf);

/*!
 * \brief Set the given network address string buffer to a null/nil value.
 * \param b The address to nullify. Nothing is done if the pointer is NULL itself.
 * \see \c janus_network_address_string_buffer_is_null
 */
void janus_network_address_string_buffer_nullify(janus_network_address_string_buffer *b);

/*!
 * \brief Test if a given network address string buffer is null-valued
 * \param b The buffer to check
 * \return A positive integer if the given buffer is null-valued, 0 otherwise.
 * \see \c janus_network_address_string_buffer_nullify
 */
int janus_network_address_string_buffer_is_null(const janus_network_address_string_buffer *b);

/*!
 * \brief Extract the human readable representation of a network address from a given buffer.
 * \param b The buffer containing the given network
 * \return A pointer to the human readable representation of the network address inside the given buffer, or NULL if the buffer is invalid or NULL.
 * \see \c janus_network_address_to_string_buffer
 */
const char *janus_network_address_string_from_buffer(const janus_network_address_string_buffer *b);

/*!
 * \brief Test if a given IP address string is a valid address of the specified type
 * \param addr_type The type of address you're interested in (janus_network_query_options_ipv4,
 * janus_network_query_options_ipv6 or janus_network_query_options_any_ip)
 * \param user_value The IP address string to check
 * \return A positive integer if the given string is a valid address, 0 otherwise.
 */
int janus_network_string_is_valid_address(janus_network_query_options addr_type, const char *user_value);

/*!
 * \brief Convert an IP address string to a janus_network_address instance
 * \param addr_type The type of address you're interested in (janus_network_query_options_ipv4,
 * janus_network_query_options_ipv6 or janus_network_query_options_any_ip)
 * \param user_value The IP address string to check
 * \param result Pointer to a valid janus_network_address instance that will contain the result
 * \return 0 in case of success, -EINVAL otherwise otherwise
 */
int janus_network_string_to_address(janus_network_query_options addr_type, const char *user_value, janus_network_address *result);

/*!
 * \brief Convert an interface name or IP address to a janus_network_address instance
 * \param ifas The list of interfaces to look into (e.g., as returned from getifaddrs)
 * \param iface The interface name or IP address to look for
 * \param result Pointer to a valid janus_network_address instance that will contain the result
 * \return 0 in case of success, -EINVAL otherwise otherwise
 */
int janus_network_lookup_interface(const struct ifaddrs *ifas, const char *iface, janus_network_address *result);

/*!
 * \brief Helper method to find a valid local IP address, that is an address that can be used to communicate
 * \param addr_type The type of address you're interested in (janus_network_query_options_ipv4,
 * janus_network_query_options_ipv6 or janus_network_query_options_any_ip)
 * \param result Pointer to a valid janus_network_address instance that will contain the result
 * \return 0 in case of success, -EINVAL otherwise otherwise
 */
int janus_network_detect_local_ip(janus_network_query_options addr_type, janus_network_address *result);

/*!
 * \brief Wrapper to janus_network_detect_local_ip that returns a string instead
 * \note The string is allocated with g_strdup and so needs to be freed by the caller
 * \param addr_type The type of address you're interested in (janus_network_query_options_ipv4,
 * janus_network_query_options_ipv6 or janus_network_query_options_any_ip)
 * \return 0 in case of success, -EINVAL otherwise otherwise
 */
char *janus_network_detect_local_ip_as_string(janus_network_query_options addr_type);
///@}

#endif

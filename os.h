/*! \file    os.h
 * \author   Marcin Sielski <marcin.sielski@gmail.com>
 * \copyright GNU General Public License v3
 * \brief    OS comapatibility layer (headers)
 * \details  Implementation of OS specific incompatibilities.
 * Should be included after all header files.
 * \ingroup core
 * \ref core
 */

#ifndef _JANUS_OS_H
#define _JANUS_OS_H

#ifdef _WIN32
#include <io.h>
#include <ws2tcpip.h>
#define IFF_RUNNING 0xFFFFFFFF
#define SO_REUSEPORT SO_REUSEADDR
#endif

#ifdef _WIN32
#ifdef SHARED
#define JANUS_API __declspec(dllexport) 
#else
#define JANUS_API __declspec(dllimport)
#endif
#define JANUS_LOCAL JANUS_API
#else
#define JANUS_API
#define JANUS_LOCAL static
#endif

#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN __ORDER_BIG_ENDIAN__
#endif

#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
#endif

#ifndef __BYTE_ORDER
#define __BYTE_ORDER __BYTE_ORDER__
#endif

#ifndef LOCK_SH
#define LOCK_SH 1 // shared lock
#endif

#ifndef LOCK_EX
#define LOCK_EX 2 // exclusive lock
#endif

#ifndef LOCK_NB
#define LOCK_NB 4 // nonblocking request
#endif

#ifndef LOCK_UN
#define LOCK_UN 8 // remove an existing lock
#endif

#ifndef HAVE_UINT
typedef unsigned int uint;
#endif

#ifndef HAVE_NDFS_T
typedef unsigned long int nfds_t;
#endif

#ifndef HAVE_IN_ADDR_T
typedef u_long in_addr_t;
#endif

#ifndef HAVE_STRUCT_IFADDRS

// http://man7.org/linux/man-pages/man3/getifaddrs.3.html
struct ifaddrs {
	struct ifaddrs  *ifa_next;    /* Next item in list */
	char            *ifa_name;    /* Name of interface */
	unsigned int     ifa_flags;   /* Flags from SIOCGIFFLAGS */
	struct sockaddr *ifa_addr;    /* Address of interface */
	struct sockaddr *ifa_netmask; /* Netmask of interface */
	union {
		struct sockaddr *ifu_broadaddr;
						/* Broadcast address of interface */
		struct sockaddr *ifu_dstaddr;
						/* Point-to-point destination address */
	} ifa_ifu;
#define              ifa_broadaddr ifa_ifu.ifu_broadaddr
#define              ifa_dstaddr   ifa_ifu.ifu_dstaddr
	void            *ifa_data;    /* Address-specific data */
};

#endif

#ifndef HAVE_POLL

/*! \brief poll - wait for some event on a file descriptor
* @param fds set of file descriptors to be monitored
* @param nfds number of file descriptors
* @param timeout number of milliseconds that poll should block
* waiting for a file descriptor to become ready.
* @returns positive number in case of success, -1 otherwise */
JANUS_API int poll(struct pollfd *fds, nfds_t nfds, int timeout);

#endif

#ifndef HAVE_INET_ATON

/*! \brief inet_aton - converts the Internet host address from the IPv4
* numbers-and-dots notation into binary form 
* @param cp Internet host address
* @param addr address binary structure
* @returns nonzero if the address is valid, a zero otherwise */
JANUS_API unsigned long inet_aton(register const char *cp, struct in_addr *addr);

#endif

#ifndef HAVE_GETIFADDRS

/*! \brief getifaddrs - get interface addresses
* @param ifpp list of interface addresses
* @returns zero in case of success, -1 otherwise */
JANUS_API int getifaddrs(struct ifaddrs **ifpp);

#endif

#ifndef HAVE_FREEIFADDRS 

/*! \brief freeifaddrs - frees interface addresses
* @param ifp list of interface addresses */
JANUS_API void freeifaddrs(struct ifaddrs *ifp);

#endif

#ifndef HAVE_STRCASESTR

/*! \brief strcasestr - locate a substring in a string (case insensitive)
* @param heystak string
* @param needle substring to locaate
* @returns If needle is an empty string, heystack is returned; if needle occurs
* nowhere in heystack, NULL is returned; otherwise a pointer to the first
* character of the first occurrence of needle is returned */
JANUS_API char *strcasestr(const char *haystack, const char *needle);

#endif

#ifndef HAVE_FLOCK

/*! \brief flock - apply or remove an advisory lock on an open file
* @param fd file descriptor
* @param operation LOCK_SH, LOCK_EX, LOCK_UN, LOCK_NB
* @returns zero in case of susscess, -1 otherwise */
JANUS_API int flock (int fd, int operation);

#endif

#endif

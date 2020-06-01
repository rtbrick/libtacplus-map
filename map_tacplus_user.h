/*
 * Copyright 2015, 2016, Cumulus Networks, Inc.  All rights reserved.
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Dave Olson <olson@cumulusnetworks.com>
 */

#ifndef MAP_TACPLUS_USER_H
#define MAP_TACPLUS_USER_H

#include <stdint.h>
#include <time.h>
#include <pwd.h>
#include <utmp.h>

#define MAP_TACPLUS_FILE "/var/run/tacacs_client_map"

#define MAP_FILE_VERSION 2 /*  version two adds tac_mapflags (compatible) */

#define MAP_USERHOMEDIR 0x1 /* tac_mapflags: separate homedirs per account */

/*
 * Structure to maintain mapping between login name and mapped tacacs name.
 * Only live while session is active.  Like utmp, designed to re-use slots
 * after session is gone.
 * Designed so that it should have the same layout in 32 and 64 bit,
 * although currently only in use on 64 bit systems.
 * Unlike utmp we do not maintain a login pid, because the PID we could
 * record will not be the PID we want check.
 */
struct tacacs_mapping {
    struct timeval tac_tv;  /* only used for debug for now */
# if __WORDSIZE == 32
    uint32_t __fill__[2]; /* to keep alignment the same for 32 and 64 bit */
#endif
    uint16_t tac_mapversion; /* mapping version that wrote this file */
    uint16_t tac_mapflags; /* flags such as MAP_USERHOMEDIR */
    uint32_t tac_session; /* session ID */
    uid_t tac_mapuid; /* for faster lookup, the login auid */
    char tac_logname[UT_NAMESIZE+1]; /* login name.  from utmp.h, + 1 for \0 */
    char tac_mappedname[UT_NAMESIZE+1]; /* mapped name, for uid we are using */
    char tac_rhost[UT_HOSTSIZE+1]; /* ssh, etc. originating host, for logging */
};

/* Returns rtbrick predefined user*/
void get_mapuser(char *role, unsigned priv_level, char *user);

/* update the mapped user database */
int update_mapuser(char *user, unsigned priv_level,
    char *host, char *role, unsigned); /* returns true/false */
char *get_user_to_auth(char *pamuser); /* returns NULL or strdup'ed memory */
unsigned map_get_sessionid(void); /* return the sessionid for this session */

/*
 * Lookup the mapped name (i.e. tacacs15) to see if there is a match, in the
 * mapping file.  and return the mapped original login name, if so.  Otherwise
 * returns the name passed as first argument.  Passing name as NULL
 * requests match on auid and session only.
 *
 * If the returned pointer != first arg and non-NULL, caller should free it.
 *
 * This only works while a mapped user is logged in, and since the auid and
 * session are lookup keys, only for processes that are descendents
 * of the mapped login, unless they are passed as wildcards (-1)
 *
 * if host is non-NULL, *host is set to the originating rhost, if any
 * It is a malloc'ed entry, and should be freed by the caller
 */
char *lookup_logname(const char *mapname, uid_t auid, unsigned session,
    char **host, uint16_t *flags);

/*
 * Similar to lookup_logname(), but by uid.
 * The same caveat applies; only works for descendent processes.
 * Returns the original login username, and the mapped name
 * in the copied to the buffered pointed to by mapped
 * Returns NULL if not found.  If non-NULL, the returned
 * pointer should be freed by the caller.
 */
char *lookup_mapuid(uid_t uid, uid_t auid, unsigned session,
                    char *mappedname, size_t maplen, uint16_t *flags);

/*
 * Like lookup_logname(), but matches on the original login name,
 * and returns the matching mapped name (e.g, tacacs0) if found,
 * otherwise returns the logname argument.  auid and session
 * will most commonly be -1 wildcards for this function.
 */
char *lookup_mapname(const char *logname, uid_t auid, unsigned session,
    char **host, uint16_t *flags);

/* This is not a public entry point, it's a helper routine for pam_tacplus */
void __update_loguid(char *);

#endif

/* SPDX-License-Identifier: AGPL-3.0-or-later */

/*
 * dav-next-module.h
 * Module configuration and initialization for dav-next
 * Copyright © 2022-2025 Alexandre Jousset
 */

#ifndef DAV_NEXT_MODULE_H
#define DAV_NEXT_MODULE_H

char *dav_next_server_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *dav_next_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
void *dav_next_create_loc_conf(ngx_conf_t *cf);
char *dav_next_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
ngx_int_t dav_next_init(ngx_conf_t *cf);

#endif // DAV_NEXT_MODULE_H

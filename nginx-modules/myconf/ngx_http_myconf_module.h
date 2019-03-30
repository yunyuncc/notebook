#ifndef NGX_HTTP_MY_CONF_MODULE_H__
#define NGX_HTTP_MY_CONF_MODULE_H__

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_module.h>

typedef struct {
    ngx_str_t       my_str;
    ngx_int_t       my_int;
    ngx_flag_t      my_flag;
    size_t          my_size;
    ngx_array_t*    my_str_array;
    ngx_array_t*    my_keyval; 
    off_t           my_off;
    ngx_msec_t      my_msec;
    time_t          my_sec;
    ngx_bufs_t      my_bufs;
    ngx_uint_t      my_enum_seq;
    ngx_uint_t      my_bitmask;
    ngx_uint_t      my_access;
    ngx_path_t*     my_path;
} ngx_http_myconf_conf_t;


#endif

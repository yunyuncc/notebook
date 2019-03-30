#include "ngx_http_myconf_module.h"

static char* ngx_http_myconf_merge_loc_conf(ngx_conf_t*cf, void*parent, void*child);
static void* ngx_http_myconf_create_loc_conf(ngx_conf_t*cf);
static char* ngx_http_myconf_slot(ngx_conf_t *cf, ngx_command_t*cmd, void*conf);
static ngx_int_t ngx_http_myconf_handler(ngx_http_request_t* r);
static ngx_int_t ngx_send_body(ngx_http_request_t *r, const char* body, const char* mime_type);
static ngx_http_module_t myconf_http_module_interface = {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_http_myconf_create_loc_conf,
    ngx_http_myconf_merge_loc_conf
};
static ngx_command_t ngx_http_myconf_commands[] = {
    {
        ngx_string("myconf"),
        NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
        ngx_http_myconf_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        0, 
        NULL
    },
    {
        ngx_string("my_flag"),
        NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_myconf_conf_t, my_flag),
        NULL
    },
    {
        ngx_string("my_str"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_myconf_conf_t, my_str),
        NULL
    },
    ngx_null_command
};

ngx_module_t ngx_http_myconf_module = {
    NGX_MODULE_V1,
    &myconf_http_module_interface,//http_module interface
    ngx_http_myconf_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};

static char* ngx_http_myconf_slot(ngx_conf_t *cf, ngx_command_t*cmd, void*conf){
    ngx_http_core_loc_conf_t *clcf = NULL;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_myconf_handler;
    return NGX_CONF_OK;
}
static ngx_int_t ngx_http_myconf_handler(ngx_http_request_t* r){
    if(r == NULL) return NGX_ERROR;
    ngx_http_myconf_conf_t* loc_conf = NULL;
    loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_myconf_module);
    if(loc_conf == NULL){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "can not get loc conf");
        return NGX_ERROR;
    }
    u_char buf[128] = "";
    ngx_snprintf(buf, sizeof(buf), "hello myconf, my_flag = %ld my_str=%V", loc_conf->my_flag,
            &loc_conf->my_str);
    return ngx_send_body(r, (char*)buf, "text/plain");
}

static ngx_int_t ngx_send_body(ngx_http_request_t *r, const char* body, const char* mime_type){
	ngx_str_t type;// = ngx_string("text/plain");
    type.data= (u_char*)mime_type;
    type.len = strlen(mime_type);
	ngx_str_t response;// = ngx_string("Hello World! 15:05");
    response.data = (u_char*)body;
    response.len = strlen(body);
	r->headers_out.content_length_n = response.len;
	r->headers_out.content_type = type;
	ngx_int_t rc = ngx_http_send_header(r);
	if(rc == NGX_ERROR || rc > NGX_OK || r->header_only){
		return rc;
	}
	ngx_buf_t *b;
	b = ngx_create_temp_buf(r->pool, response.len);
	if(b == NULL){
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	ngx_memcpy(b->pos, response.data, response.len);
	b->last = b->pos + response.len;
	b->last_buf = 1;
	ngx_chain_t out;
	out.buf = b;
	out.next = NULL;
	return ngx_http_output_filter(r, &out);

}
static void* ngx_http_myconf_create_loc_conf(ngx_conf_t*cf){
    ngx_http_myconf_conf_t* mycf = NULL;
    mycf = ngx_pcalloc(cf->pool, sizeof(ngx_http_myconf_conf_t));
    if(mycf == NULL){
        return NULL;
    }
    mycf->my_flag = NGX_CONF_UNSET;
    return mycf;
}
static char* ngx_http_myconf_merge_loc_conf(ngx_conf_t*cf, void*parent, void*child){
    ngx_http_myconf_conf_t *prev = (ngx_http_myconf_conf_t*)parent;
    ngx_http_myconf_conf_t *conf = (ngx_http_myconf_conf_t*)child;
    ngx_conf_merge_str_value(conf->my_str, prev->my_str, "default_str");
    return NGX_CONF_OK;
}

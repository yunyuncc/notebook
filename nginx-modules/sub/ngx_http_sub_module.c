#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_module.h>
typedef struct {
    ngx_http_status_t status;
    ngx_str_t upstream_domain;
    ngx_str_t upstream_uri;
    ngx_str_t upstream_args;
} ngx_http_sub_ctx_t;


static void sub_post_handler(ngx_http_request_t *r);
static ngx_int_t sub_subrequest_post_handler(ngx_http_request_t* r, void*data, ngx_int_t rc);
static ngx_http_sub_ctx_t* create_ctx_if_null(ngx_http_request_t * r);
static char* ngx_http_sub(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_sub_handler(ngx_http_request_t *r);

typedef struct{
    ngx_int_t a;
} ngx_http_sub_conf_t;


static ngx_command_t ngx_http_sub_commands[] = {
	{
		ngx_string("sub"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF/*what is this?*/|NGX_CONF_NOARGS,
		ngx_http_sub,
		NGX_HTTP_LOC_CONF_OFFSET,//what is this?
		0,
		NULL
	},
	ngx_null_command
};

static ngx_http_module_t ngx_http_sub_module_ctx = {
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};


ngx_module_t ngx_http_sub_module = {
	NGX_MODULE_V1,
	&ngx_http_sub_module_ctx,//http module interface
	ngx_http_sub_commands,
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

static ngx_int_t ngx_sub_send_body(ngx_http_request_t *r, const char* body, const char* mime_type){
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
static ngx_http_sub_ctx_t* create_ctx_if_null(ngx_http_request_t * r){
    ngx_http_sub_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_sub_module);
    if(ctx == NULL){
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_sub_ctx_t));
        if(ctx == NULL) return NULL;
        ngx_http_set_ctx(r, ctx, ngx_http_sub_module);
    }
    return ctx;
}
static ngx_int_t ngx_http_sub_handler(ngx_http_request_t *r){
	if(!(r->method &(NGX_HTTP_GET|NGX_HTTP_HEAD))){
		return NGX_HTTP_NOT_ALLOWED;
	}
    ngx_http_sub_ctx_t* ctx = create_ctx_if_null(r);
    if(ctx == NULL){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "create ctx fail");
        return NGX_ERROR;
    }
    ngx_http_post_subrequest_t* psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if(psr == NULL){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "alloc error");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    psr->handler = sub_subrequest_post_handler;
    psr->data = ctx;
    ngx_str_t sub_uri = ngx_string("/test");
    ngx_str_t sub_args = ngx_string("args1=11&args2=22");
    ngx_http_request_t *sr = NULL;
    ngx_int_t rc = ngx_http_subrequest(r, &sub_uri, &sub_args, &sr, psr, NGX_HTTP_SUBREQUEST_IN_MEMORY);
    if(rc != NGX_OK){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "subrequest fail");
        return NGX_ERROR;
    }
    return NGX_DONE;
}
static char* ngx_http_sub(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
	ngx_http_core_loc_conf_t *clcf;
	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);//what is this
	clcf->handler = ngx_http_sub_handler;
	ngx_log_stderr(0, "ngx_http_sub  called");
	return NGX_CONF_OK;
}

static ngx_int_t sub_subrequest_post_handler(ngx_http_request_t* r, void*data, ngx_int_t rc){
    ngx_http_request_t* pr = r->parent;
    ngx_log_t*log = r->connection->log;
    pr->headers_out.status = r->headers_out.status;
    if(r->headers_out.status == NGX_HTTP_OK){
        ngx_log_error(NGX_LOG_INFO, log, 0, "status ok");
        ngx_buf_t* buf = &r->upstream->buffer;
        ngx_str_t str;
        str.data = buf->pos;
        str.len = buf->last- buf->pos;
        ngx_log_error(NGX_LOG_INFO, log, 0, " str[%V]", &str);
    }
    pr->write_event_handler = sub_post_handler;
    


    //ngx_http_postponed_request_t* postponed = pr->postponed;
    //if(postponed == NULL){
    //    ngx_log_error(NGX_LOG_INFO, log, 0, "postponed null");
    //    return NGX_ERROR;
    //}
    //for(; postponed != NULL; postponed = postponed->next){
    //    ngx_log_error(NGX_LOG_INFO, log, 0, "has a postponed");
    //    ngx_chain_t* out = postponed->out;
    //    if(out == NULL) continue;
    //    ngx_log_error(NGX_LOG_INFO, log, 0, "postponed has out");
    //}
    return NGX_OK;
}
static void sub_post_handler(ngx_http_request_t *r){
    if(r->headers_out.status != NGX_HTTP_OK){
        ngx_http_finalize_request(r, r->headers_out.status);
        return;
    }
    //ngx_http_sub_ctx_t* ctx = create_ctx_if_null(r);
    ngx_int_t rc = ngx_sub_send_body(r, "post handler hello", "text/plain");
    ngx_http_finalize_request(r, rc);
}

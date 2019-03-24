#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_module.h>
typedef struct {
    ngx_http_status_t status;
    ngx_str_t upstream_domain;
    ngx_str_t upstream_uri;
    ngx_str_t upstream_args;
} ngx_http_mytest_ctx_t;


static void mytest_upstream_finalize_request(ngx_http_request_t *r, ngx_int_t rc);
static ngx_int_t mytest_upstream_process_header(ngx_http_request_t*r);
static ngx_int_t mytest_upstream_process_status_line(ngx_http_request_t *r);
static ngx_int_t mytest_upstream_create_request(ngx_http_request_t *r);
static ngx_http_mytest_ctx_t* create_ctx_if_null(ngx_http_request_t * r);
static char* ngx_http_mytest_merge_loc_conf(ngx_conf_t* cf, void*parent, void*child);
static char* ngx_http_mytest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_mytest_handler(ngx_http_request_t *r);
static void* ngx_http_mytest_create_loc_conf(ngx_conf_t*cf);

typedef struct{
    ngx_http_upstream_conf_t upstream;
} ngx_http_mytest_conf_t;

static ngx_str_t  ngx_http_proxy_hide_headers[] = {
    ngx_string("Date"),
    ngx_string("Server"),
    ngx_null_string
};

static ngx_command_t ngx_http_mytest_commands[] = {
	{
		ngx_string("mytest"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF/*what is this?*/|NGX_CONF_NOARGS,
		ngx_http_mytest,
		NGX_HTTP_LOC_CONF_OFFSET,//what is this?
		0,
		NULL
	},
	ngx_null_command
};

static ngx_http_module_t ngx_http_mytest_module_ctx = {
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	ngx_http_mytest_create_loc_conf,
	ngx_http_mytest_merge_loc_conf
};


ngx_module_t ngx_http_mytest_module = {
	NGX_MODULE_V1,
	&ngx_http_mytest_module_ctx,//http module interface
	ngx_http_mytest_commands,
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

//static ngx_int_t ngx_mytest_send_body(ngx_http_request_t *r, const char* body, const char* mime_type){
//	ngx_str_t type;// = ngx_string("text/plain");
//    type.data= (u_char*)mime_type;
//    type.len = strlen(mime_type);
//	ngx_str_t response;// = ngx_string("Hello World! 15:05");
//    response.data = (u_char*)body;
//    response.len = strlen(body);
//	r->headers_out.content_length_n = response.len;
//	r->headers_out.content_type = type;
//	ngx_int_t rc = ngx_http_send_header(r);
//	if(rc == NGX_ERROR || rc > NGX_OK || r->header_only){
//		return rc;
//	}
//	ngx_buf_t *b;
//	b = ngx_create_temp_buf(r->pool, response.len);
//	if(b == NULL){
//		return NGX_HTTP_INTERNAL_SERVER_ERROR;
//	}
//	ngx_memcpy(b->pos, response.data, response.len);
//	b->last = b->pos + response.len;
//	b->last_buf = 1;
//	ngx_chain_t out;
//	out.buf = b;
//	out.next = NULL;
//	return ngx_http_output_filter(r, &out);
//
//}
static ngx_http_mytest_ctx_t* create_ctx_if_null(ngx_http_request_t * r){
    ngx_http_mytest_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_mytest_module);
    if(ctx == NULL){
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_mytest_ctx_t));
        if(ctx == NULL) return NULL;
        ngx_http_set_ctx(r, ctx, ngx_http_mytest_module);
    }
    return ctx;
}
ngx_int_t find_arg_value(const ngx_str_t* raw_args, const char* key, ngx_str_t*value){
    //TODO set value from raw_args

    return NGX_OK;
}
ngx_int_t find_upstream_domain(const ngx_str_t* raw_args, ngx_str_t* domain){
    if(raw_args == NULL || domain == NULL) return NGX_ERROR;   
    return find_arg_value(raw_args, "upstream_domain=", domain);
}
ngx_int_t find_upstream_uri(const ngx_str_t* raw_args, ngx_str_t* uri){
    if(raw_args == NULL || uri == NULL) return NGX_ERROR;   
    return find_arg_value(raw_args, "upstream_uri=", uri);
}

// args:
// test?upstream_domain=aaaa&upstream_uri=bbbb&args1=11&args2=22&args3=33
static ngx_int_t ngx_http_mytest_handler(ngx_http_request_t *r){
	if(!(r->method &(NGX_HTTP_GET|NGX_HTTP_HEAD))){
		return NGX_HTTP_NOT_ALLOWED;
	}
    ngx_http_mytest_ctx_t* ctx = create_ctx_if_null(r);
    if(ctx == NULL){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "create ctx fail");
        return NGX_ERROR;
    }

    if(ngx_http_upstream_create(r) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_http_upstream_create failed");
        return NGX_ERROR;
    }
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "upstream handler called, args[%V]", &r->args);
    
    //TODO get upstream_domain, upstream_uri, upstream_args and set it to ctx
    
    if(NGX_OK != find_upstream_domain(&r->args, &ctx->upstream_domain)){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "find_upstream_domain fail");
    }
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "upstream_domain[%V]", &ctx->upstream_domain);
    ngx_log_t*log = r->connection->log;
    ngx_http_mytest_conf_t *cf = (ngx_http_mytest_conf_t*) ngx_http_get_module_loc_conf(r, ngx_http_mytest_module);
    if(cf == NULL){
        ngx_log_error(NGX_LOG_INFO, log, 0, "cf is NULL");
        return NGX_ERROR;
    }
    ngx_http_upstream_t * u = r->upstream;
    u->conf = &cf->upstream;
    u->buffering = cf->upstream.buffering;
    u->resolved = (ngx_http_upstream_resolved_t*) ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
    if(u->resolved == NULL){
        ngx_log_error(NGX_LOG_ERR, log, 0, "pcalloc ngx_http_upstream_resolved_t fail");
        return NGX_ERROR;
    }
    //TODO get ip from upstream_domain
    static struct sockaddr_in backend_sock_addr;
    backend_sock_addr.sin_family = AF_INET;
    backend_sock_addr.sin_port = htons((in_port_t) 8000);
    backend_sock_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    u->resolved->sockaddr = (struct sockaddr *)&backend_sock_addr;
    u->resolved->socklen = sizeof(struct sockaddr_in);
    u->resolved->naddrs = 1;
    u->resolved->port = htons((in_port_t) 8000);
    u->create_request = mytest_upstream_create_request;
    u->process_header = mytest_upstream_process_status_line;
    u->finalize_request = mytest_upstream_finalize_request;
    r->main->count++;
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "before ngx_http_upstream_init");
    ngx_http_upstream_init(r);
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "after ngx_http_upstream_init");
    return NGX_DONE;
}
static char* ngx_http_mytest(ngx_conf_t *cf, ngx_command_t *cmd, void *conf){
	ngx_http_core_loc_conf_t *clcf;
	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);//what is this
	clcf->handler = ngx_http_mytest_handler;
	ngx_log_stderr(0, "ngx_http_mytest  called");
	return NGX_CONF_OK;
}

static void* ngx_http_mytest_create_loc_conf(ngx_conf_t*cf){
    ngx_http_mytest_conf_t* mycf = NULL;
    mycf = (ngx_http_mytest_conf_t*)ngx_pcalloc(cf->pool, sizeof(ngx_http_mytest_conf_t));
    if(mycf == NULL){
        return NULL;
    }
    mycf->upstream.connect_timeout = 1000;
    mycf->upstream.send_timeout = 2000;
    mycf->upstream.read_timeout = 3000;
    mycf->upstream.store_access = 0600;
    mycf->upstream.buffering = 0;
    mycf->upstream.bufs.num = 8;
    mycf->upstream.bufs.size = ngx_pagesize;
    mycf->upstream.buffer_size = ngx_pagesize;

    mycf->upstream.busy_buffers_size = 2*ngx_pagesize;
    mycf->upstream.temp_file_write_size = 2*ngx_pagesize;
    mycf->upstream.max_temp_file_size = 1024*1024*1024;
    mycf->upstream.hide_headers = NGX_CONF_UNSET_PTR;//not null
    mycf->upstream.pass_headers = NGX_CONF_UNSET_PTR;
    ngx_log_error(NGX_LOG_INFO, cf->log, 0, "mytest create loc conf");
    return mycf;
}
static char* ngx_http_mytest_merge_loc_conf(ngx_conf_t* cf, void*parent, void*child){
    ngx_http_mytest_conf_t *prev = (ngx_http_mytest_conf_t*)parent;
    ngx_http_mytest_conf_t *conf = (ngx_http_mytest_conf_t*)child;
    ngx_hash_init_t hash;
    hash.max_size = 100;
    hash.bucket_size = 1024;
    hash.name = "proxy_headers_hash";
    if(ngx_http_upstream_hide_headers_hash(cf, &conf->upstream, &prev->upstream, ngx_http_proxy_hide_headers, &hash) != NGX_OK){
        return NGX_CONF_ERROR;
    }
    ngx_log_error(NGX_LOG_INFO, cf->log, 0, "mytest merge loc conf");
    return NGX_CONF_OK;
}
static const char* upstream_uri = "/hello";
//upstream callback
static ngx_int_t mytest_upstream_create_request(ngx_http_request_t *r){
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,"create request callback");
    //TODO get upstream_uri from ctx
    //TODO get upstream_args from ctx
    static ngx_str_t backend_query_line = ngx_string("GET %s?%V HTTP/1.1\r\nConnection: close\r\n\r\n");
    ngx_int_t queryline_len = backend_query_line.len + r->args.len - 2 + strlen(upstream_uri) -2 ;
    ngx_buf_t* b = ngx_create_temp_buf(r->pool, queryline_len);
    if(b == NULL){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "create temp buf fail when create request");
        return NGX_ERROR;
    }
    b->last = b->pos + queryline_len;
    ngx_snprintf(b->pos, queryline_len, (char*)backend_query_line.data, upstream_uri, &r->args);
    r->upstream->request_bufs = ngx_alloc_chain_link(r->pool);
    if(r->upstream->request_bufs == NULL){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "alloc chain link fail when create request");
        return NGX_ERROR;
    }
    r->upstream->request_bufs->buf = b;
    r->upstream->request_bufs->next = NULL;
    r->upstream->request_sent = 0;
    r->upstream->header_sent = 0;
    r->header_hash = 1;
    return NGX_OK;
}
static ngx_int_t mytest_upstream_process_status_line(ngx_http_request_t *r){
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "process status line callback");
    size_t len = 0;
    ngx_int_t rc = NGX_OK;
    ngx_http_upstream_t *u = NULL;
    ngx_http_mytest_ctx_t* ctx = ngx_http_get_module_ctx(r, ngx_http_mytest_module);
    if(ctx == NULL){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "get ctx fail when process status line");
        return NGX_ERROR;
    }    
    u = r->upstream;
    rc = ngx_http_parse_status_line(r, &u->buffer, &ctx->status);
    if(rc == NGX_AGAIN){
        return rc;
    }
    if(rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "upstream sent no valid HTTP/1.0 header");
        r->http_version = NGX_HTTP_VERSION_9;
        u->state->status = NGX_HTTP_OK;
        return NGX_OK;
    }
    if (u->state){
        u->state->status = ctx->status.code;
    }
    u->headers_in.status_n = ctx->status.code;
    len = ctx->status.end - ctx->status.start;
    u->headers_in.status_line.data = ngx_pnalloc(r->pool, len);
    if(u->headers_in.status_line.data == NULL){
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "alloc status_line when process status line");
        return NGX_ERROR;
    }
    ngx_memcpy(u->headers_in.status_line.data, ctx->status.start, len);
    u->process_header = mytest_upstream_process_header;
    return mytest_upstream_process_header(r);
}

static ngx_int_t mytest_upstream_process_header(ngx_http_request_t*r){
    ngx_log_error(NGX_LOG_INFO, r->connection->log,0, "process header line callback");
    ngx_int_t rc = NGX_OK;
    ngx_table_elt_t *h = NULL;
    ngx_http_upstream_header_t *hh = NULL;
    ngx_http_upstream_main_conf_t *umcf = NULL;
    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    for(;;){
        rc = ngx_http_parse_header_line(r, &r->upstream->buffer, 1);
        if(rc == NGX_OK) {// get a header line success
            h = ngx_list_push(&r->upstream->headers_in.headers);
            if(h == NULL){
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "lish push fail when parse header line");
                return NGX_ERROR;
            }
            h->hash = r->header_hash;
            h->key.len = r->header_name_end -r->header_name_start;
            h->value.len = r->header_end - r->header_start;
            h->key.data = ngx_pnalloc(r->pool, h->key.len+1 + h->value.len+1 +h->key.len+1);//?
            if(h->key.data == NULL){
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "alloc fail when parse header line");
                return NGX_ERROR;
            }
            h->value.data = h->key.data + h->key.len + 1;
            h->lowcase_key = h->key.data + h->key.len+1 + h->value.len+1;
            ngx_memcpy(h->key.data, r->header_name_start, h->key.len);
            h->key.data[h->key.len] = '\0';
            ngx_memcpy(h->value.data, r->header_start, h->value.len);
            h->value.data[h->value.len] = '\0';
            if(h->key.len == r->lowcase_index) {
                ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);
            }else{
                ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
            }
            hh = ngx_hash_find(&umcf->headers_in_hash, h->hash, h->lowcase_key, h->key.len);
            if(hh && hh->handler(r, h, hh->offset) != NGX_OK){
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "hash_find when parse header line");
                return NGX_ERROR;
            }
            continue;
        }
        if(rc == NGX_HTTP_PARSE_HEADER_DONE){// all headers done
            if(r->upstream->headers_in.server == NULL){
                h = ngx_list_push(&r->upstream->headers_in.headers);
                if(h == NULL){
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "list push fail when parse header line done");
                    return NGX_ERROR;
                }
                h->hash = ngx_hash(ngx_hash(ngx_hash(ngx_hash(ngx_hash('s', 'e'), 'r'), 'v'), 'e'), 'r');
                ngx_str_set(&h->key, "Server");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char*)"server";
            }
            if(r->upstream->headers_in.date == NULL){
                h = ngx_list_push(&r->upstream->headers_in.headers);
                if(h == NULL) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "list push fail when parse header line done");
                    return NGX_ERROR;
                }
                h->hash = ngx_hash(ngx_hash(ngx_hash('d', 'a'), 't'), 'e');
                ngx_str_set(&h->key, "Date");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char*) "date";
            }
            return NGX_OK;
        }
        if(rc == NGX_AGAIN){
            return NGX_AGAIN;
        }
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "upstream sent invalid header");
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }
}

static void mytest_upstream_finalize_request(ngx_http_request_t *r, ngx_int_t rc){
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "mytest upstream finalize request");
}

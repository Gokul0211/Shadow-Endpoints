"""
Names of every toggleable extractor and phase.

Each name can be switched off (--disable-extractor NAME), or all but a chosen
few can be switched off (--only-extractor NAME), so ablations (leave-one-out /
add-one-in) run on the real pipeline. Every evidence item records the name of
the extractor that produced it, so per-technique attribution comes from data.

CODE_EXTRACTORS run on each analysed blob of JS, in this fixed order (the order
matters: see EnhancedStaticAnalyzer.analyze_code). Infrastructure steps that
only queue more files to fetch (dynamic imports, lazy chunk paths) are not
listed: switching them off would change *what is analysed*, not what is found.
"""

# (name, method on EnhancedStaticAnalyzer)
CODE_EXTRACTORS = [
    ('ast_layer', '_run_ast_layer'),
    # HTTP clients
    ('angular_http', '_extract_angular_http_calls'),
    ('named_axios', '_extract_named_axios_calls'),
    ('nextjs_routes', '_extract_nextjs_routes'),
    ('internal_ip', '_extract_internal_ip_urls'),
    ('env_var_urls', '_extract_env_var_urls'),
    # framework conventions
    ('trpc', '_extract_trpc_procedures'),
    ('nuxt_server', '_extract_nuxt_server_routes'),
    ('graphql_tag', '_extract_graphql_tag_operations'),
    ('tanstack_routes', '_extract_tanstack_routes'),
    ('jsdoc_openapi', '_extract_jsdoc_openapi'),
    ('rtk_query', '_extract_rtk_query_endpoints'),
    ('query_hooks', '_extract_query_hooks'),
    # URL-builder functions
    ('interprocedural', '_extract_interprocedural_calls'),
    # call sites, sockets, SOAP
    ('router_navigation', '_extract_router_navigation'),
    ('fetch_and_hooks', '_extract_fetch_and_hook_calls'),
    ('url_constructor', '_extract_url_constructor_calls'),
    ('dynamic_websockets', '_extract_dynamic_websockets'),
    ('url_builder_calls', '_extract_url_builder_calls'),
    ('promise_chains', '_extract_promise_chain_calls'),
    ('interceptor_base', '_extract_interceptor_base_urls'),
    ('websocket_literals', '_extract_websocket_literals'),
    ('soap_calls', '_extract_soap_calls'),
    # storage / navigation / broad literal sweeps
    ('indexeddb_keys', '_extract_indexeddb_cache_keys'),
    ('history_navigation', '_extract_history_navigation'),
    ('location_routes', '_extract_location_and_hash_routes'),
    ('template_literals', '_extract_resolved_template_literals'),
    ('api_literals', '_extract_api_string_literals'),
    ('external_literals', '_extract_external_subdomain_literals'),
    ('linkfinder_sweep', '_linkfinder_sweep'),
]

# Steps of EnhancedStaticAnalyzer.scan() outside analyze_code
SCAN_EXTRACTORS = [
    'rpc_patterns', 'array_harvest', 'service_properties', 'json_config',
    'webpack_modules', 'static_websockets', 'graphql_introspection', 'value_flow',
]

# Pipeline phases (pipeline.py). Phase 1 (discovery) always runs.
PHASES = ['1.5', '2', '1.55', '1.6', '1.75', '1.8', '1.85', '2.5', '3', '1.5b']


def extractor_names():
    return [n for n, _ in CODE_EXTRACTORS] + SCAN_EXTRACTORS

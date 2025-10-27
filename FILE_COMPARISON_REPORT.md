# File Comparison Report: Root vs dlnk_FINAL

## Summary

- Common files: 276
- Files only in root: 216
- Files only in dlnk_FINAL: 6

## Files Only in Root

- `advanced_agents/backdoor_installer.py`
- `advanced_agents/crash_triager.py`
- `advanced_agents/exploit_gen/bypass_generator.py`
- `advanced_agents/exploit_gen/exploit_template.py`
- `advanced_agents/exploit_gen/heap_spray.py`
- `advanced_agents/exploit_gen/payload_encoder.py`
- `advanced_agents/exploit_gen/rop_generator.py`
- `advanced_agents/exploit_gen/shellcode_generator.py`
- `advanced_agents/exploit_generator.py`
- `advanced_agents/exploit_validation/exploit_tester.py`
- `advanced_agents/fuzzing/afl_fuzzer.py`
- `advanced_agents/fuzzing/corpus_manager.py`
- `advanced_agents/fuzzing/crash_analyzer.py`
- `advanced_agents/fuzzing/grammar_fuzzer.py`
- `advanced_agents/fuzzing/libfuzzer_wrapper.py`
- `advanced_agents/keylogger.py`
- `advanced_agents/screenshot.py`
- `advanced_agents/symbolic/angr_executor.py`
- `advanced_agents/symbolic/concolic_executor.py`
- `advanced_agents/symbolic/constraint_solver.py`
- `advanced_agents/symbolic/memory_model.py`
- `advanced_agents/symbolic/path_explorer.py`
- `advanced_agents/symbolic/state_manager.py`
- `advanced_agents/symbolic_executor.py`
- `advanced_agents/taint/dataflow_analyzer.py`
- `advanced_agents/taint/dynamic_taint.py`
- `advanced_agents/taint/sink_detector.py`
- `advanced_agents/taint/source_identifier.py`
- `advanced_agents/taint/static_taint.py`
- `advanced_agents/taint/taint_propagation.py`
- `agents/credential_harvesting/__init__.py`
- `agents/credential_harvesting/credential_harvester.py`
- `agents/evasion/__init__.py`
- `agents/evasion/anti_debug.py`
- `agents/evasion/polymorphic_generator.py`
- `agents/exploitation/__init__.py`
- `agents/exploitation/deserialization_agent.py`
- `agents/exploitation/rce_agent.py`
- `agents/exploitation/ssrf_agent.py`
- `agents/exploitation/xxe_agent.py`
- `agents/nmap_agent.py`
- `agents/persistence/__init__.py`
- `agents/persistence/linux_persistence.py`
- `agents/persistence/web_persistence.py`
- `agents/persistence/windows_persistence.py`
- `agents/pivoting/__init__.py`
- `agents/pivoting/network_pivot.py`
- `agents/post_exploitation/__init__.py`
- `agents/post_exploitation/lateral_movement.py`
- `agents/post_exploitation/privesc_agent.py`
- `agents/post_exploitation/webshell_manager.py`
- `agents/webshell_generator.py`
- `apex_ai_system_local.py`
- `api/auth_routes.py`
- `api/database/db_service.py`
- `api/database/decorators.py`
- `api/dependencies.py`
- `api/license/admin_notifications.py`
- `api/license/license_manager.py`
- `api/main_complete.py`
- `api/main_integrated.py`
- `api/main_old.py`
- `api/middleware/auth.py`
- `api/models/response.py`
- `api/routes/admin_v2.py`
- `api/routes/ai.py`
- `api/routes/attack_v2.py`
- `api/routes/auth.py`
- `api/routes/c2.py`
- `api/routes/exploit.py`
- `api/routes/fuzzing.py`
- `api/routes/knowledge.py`
- `api/routes/learning_routes.py`
- `api/routes/one_click_attack.py`
- `api/routes/scan.py`
- `api/routes/statistics.py`
- `api/routes/zeroday_routes.py`
- `api/services/attack_manager.py`
- `api/services/auth.py`
- `api/services/database.py`
- `api/services/database_sqlite.py`
- `api/services/websocket_manager.py`
- `api/websocket_handler.py`
- `apply_error_handling_fix.py`
- `c2_infrastructure/agent_handler.py`
- `c2_infrastructure/c2_server.py`
- `c2_infrastructure/protocols/dns_protocol.py`
- `c2_infrastructure/protocols/http_protocol.py`
- `c2_infrastructure/protocols/websocket_protocol.py`
- `check_admin.py`
- `cli/client.py`
- `cli/commands/__init__.py`
- `cli/commands/admin.py`
- `cli/commands/attack.py`
- `cli/commands/auth.py`
- `cli/commands/report.py`
- `cli/commands/system.py`
- `cli/config.py`
- `cli/interactive_console.py`
- `cli/loot_cli.py`
- `cli/web_redirect.py`
- `compare_files.py`
- `config/__init__.py`
- `config/env_loader.py`
- `config/settings_new.py`
- `core/advanced_c2_server.py`
- `core/advanced_reporting.py`
- `core/ai_models/ai_decision_engine.py`
- `core/ai_models/anomaly_detector.py`
- `core/ai_models/exploit_predictor.py`
- `core/ai_models/ml_vulnerability_detector.py`
- `core/ai_models/model_manager.py`
- `core/ai_models/pattern_recognizer.py`
- `core/ai_models/vulnerability_classifier.py`
- `core/ai_system/custom_ai_engine.py`
- `core/ai_system/vulnerability_analyzer.py`
- `core/attack_logger.py`
- `core/attack_workflow.py`
- `core/auto_exploit.py`
- `core/c2_protocols.py`
- `core/data_exfiltration.py`
- `core/error_handlers.py`
- `core/evasion/waf_bypass.py`
- `core/health_monitoring/__init__.py`
- `core/health_monitoring/alert_manager.py`
- `core/health_monitoring/health_monitor.py`
- `core/health_monitoring/resource_monitor.py`
- `core/llm_wrapper.py`
- `core/ml_training/data_collector.py`
- `core/ml_training/dataset_manager.py`
- `core/ml_training/feature_extractor.py`
- `core/ml_training/model_evaluator.py`
- `core/ml_training/model_trainer.py`
- `core/ml_training/training_pipeline.py`
- `core/one_click_orchestrator.py`
- `core/parallel_executor.py`
- `core/performance.py`
- `core/performance/__init__.py`
- `core/performance/cache_manager.py`
- `core/performance/performance_monitor.py`
- `core/production_monitoring.py`
- `core/rl_attack_agent.py`
- `core/security/__init__.py`
- `core/security/security_auditor.py`
- `core/self_healing.py`
- `core/self_healing/__init__.py`
- `core/self_healing/alert_manager.py`
- `core/self_healing/error_detector.py`
- `core/self_healing/health_monitor.py`
- `core/self_healing/performance_monitor.py`
- `core/self_healing/resource_monitor.py`
- `core/self_learning.py`
- `core/self_learning/__init__.py`
- `core/self_learning/adaptive_learner.py`
- `core/self_learning/pattern_learner.py`
- `core/tool_manager.py`
- `core/zeroday_notification.py`
- `database/init_db.py`
- `database/migrations/env.py`
- `database/redis_config.py`
- `fix_bare_except.py`
- `fix_critical_issues.py`
- `fix_phase2_error_handling.py`
- `fix_phase3_llm_wrapper.py`
- `fix_phase4_env_vars.py`
- `fix_phase4_env_vars_v2.py`
- `init_database.py`
- `integrations/__init__.py`
- `integrations/notifications.py`
- `integrations/siem.py`
- `llm_config_new.py`
- `protocol_exploits/dns_exploit.py`
- `protocol_exploits/ftp_exploit.py`
- `protocol_exploits/mongodb_exploit.py`
- `protocol_exploits/mssql_exploit.py`
- `protocol_exploits/mysql_exploit.py`
- `protocol_exploits/oracle_exploit.py`
- `protocol_exploits/postgresql_exploit.py`
- `protocol_exploits/rdp_exploit.py`
- `protocol_exploits/smb_exploit.py`
- `protocol_exploits/smtp_exploit.py`
- `protocol_exploits/ssh_exploit.py`
- `scripts/validate_config.py`
- `services/attack_service.py`
- `services/c2_server.py`
- `services/distributed_fuzzing.py`
- `services/file_service.py`
- `services/notification_service.py`
- `services/report_service.py`
- `services/system_service.py`
- `system_audit.py`
- `test_all_phases.py`
- `test_api_endpoints.py`
- `test_api_fixed.py`
- `test_config.py`
- `test_database_pool.py`
- `test_db_fixed.py`
- `test_full_system.py`
- `test_system_complete.py`
- `tests/comprehensive_test_suite.py`
- `tests/integration_test_suite.py`
- `tests/test_all.py`
- `tests/test_attack_logging.py`
- `tests/test_db.py`
- `tests/test_db2.py`
- `tests/test_db3.py`
- `tests/test_db4.py`
- `tests/test_development.py`
- `tests/test_e2e.py`
- `tests/test_integration.py`
- `tests/test_integration_complete.py`
- `tests/test_license_management.py`
- `tests/test_performance.py`
- `tests/test_security.py`
- `tests/test_startup.py`
- `tests/test_system.py`

## Files Only in dlnk_FINAL

- `agents/deserialization_agent.py`
- `agents/rce_agent.py`
- `agents/xxe_agent.py`
- `api/routes/auth_routes.py`
- `check_agent.py`
- `services/monitoring_service.py`

## Common Files Comparison

| File | Root Lines | dlnk Lines | Diff | Recommendation |
|------|------------|------------|------|----------------|
| `agents/active_directory/bloodhound_agent.py` | 453 | 31 | +422 | Keep root |
| `agents/active_directory/adcs_agent.py` | 392 | 15 | +377 | Keep root |
| `core/session_manager.py` | 106 | 475 | -369 | **Use dlnk_FINAL** |
| `api/routes/admin.py` | 151 | 505 | -354 | **Use dlnk_FINAL** |
| `agents/active_directory/asreproasting_agent.py` | 331 | 34 | +297 | Keep root |
| `core/ai_integration.py` | 601 | 311 | +290 | Keep root |
| `agents/zero_day_hunter_weaponized.py` | 484 | 771 | -287 | **Use dlnk_FINAL** |
| `advanced_agents/zero_day_hunter.py` | 642 | 383 | +259 | Keep root |
| `agents/lateral_movement_agent.py` | 401 | 148 | +253 | Keep root |
| `core/orchestrator.py` | 424 | 635 | -211 | **Use dlnk_FINAL** |
| `web/api.py` | 497 | 290 | +207 | Keep root |
| `agents/sqlmap_agent.py` | 459 | 259 | +200 | Keep root |
| `agents/target_acquisition_agent.py` | 566 | 428 | +138 | Keep root |
| `core/workflow_executor.py` | 47 | 152 | -105 | **Use dlnk_FINAL** |
| `agents/enhanced_privilege_escalation_agent.py` | 616 | 519 | +97 | Keep root |
| `agents/code_writer_agent.py` | 640 | 546 | +94 | Keep root |
| `core/report_generator.py` | 519 | 602 | -83 | **Use dlnk_FINAL** |
| `agents/tool_manager_agent.py` | 287 | 209 | +78 | Keep root |
| `agents/advanced_data_exfiltration_agent.py` | 663 | 586 | +77 | Keep root |
| `agents/active_directory/constrained_delegation_agent.py` | 90 | 15 | +75 | Keep root |
| `api/routes/attack.py` | 238 | 304 | -66 | **Use dlnk_FINAL** |
| `api/main.py` | 359 | 294 | +65 | Keep root |
| `agents/advanced_c2_agent.py` | 502 | 439 | +63 | Keep root |
| `core/context_manager.py` | 173 | 119 | +54 | Keep root |
| `agents/privilege_escalation_agent.py` | 193 | 147 | +46 | Keep root |
| `api/license_routes.py` | 111 | 156 | -45 | **Use dlnk_FINAL** |
| `agents/privilege_escalation_agent_weaponized.py` | 506 | 469 | +37 | Keep root |
| `advanced_agents/xss_hunter.py` | 442 | 406 | +36 | Keep root |
| `agents/advanced_backdoor_agent.py` | 442 | 410 | +32 | Keep root |
| `agents/command_injection_exploiter.py` | 518 | 487 | +31 | Keep root |
| `agents/xss_agent.py` | 468 | 437 | +31 | Keep root |
| `advanced_agents/auth_bypass.py` | 451 | 421 | +30 | Keep root |
| `llm_config.py` | 127 | 98 | +29 | Keep root |
| `agents/shell_upgrader_agent_weaponized.py` | 393 | 366 | +27 | Keep root |
| `agents/auth_agent.py` | 65 | 44 | +21 | Keep root |
| `agents/__init__.py` | 25 | 5 | +20 | Keep root |
| `cli/attack_cli.py` | 462 | 480 | -18 | **Use dlnk_FINAL** |
| `core/pubsub_manager.py` | 119 | 102 | +17 | Keep root |
| `agents/active_directory/zerologon_agent.py` | 33 | 19 | +14 | Keep root |
| `config/settings.py` | 125 | 112 | +13 | Keep root |
| `startup.py` | 307 | 297 | +10 | Keep root |
| `agents/active_directory/dcsync_agent.py` | 39 | 30 | +9 | Keep root |
| `agents/file_upload_agent.py` | 516 | 525 | -9 | **Use dlnk_FINAL** |
| `agents/active_directory/golden_ticket_agent.py` | 36 | 29 | +7 | Keep root |
| `core/vulnerability_scanner.py` | 322 | 329 | -7 | **Use dlnk_FINAL** |
| `agents/deserialization_exploiter.py` | 411 | 417 | -6 | **Use dlnk_FINAL** |
| `agents/waf_bypass_agent_weaponized.py` | 351 | 345 | +6 | Keep root |
| `api/routes/files.py` | 81 | 75 | +6 | Keep root |
| `api/routes/monitoring.py` | 420 | 414 | +6 | Keep root |
| `core/data_models.py` | 1077 | 1082 | -5 | **Use dlnk_FINAL** |
| `data_exfiltration/exfiltrator.py` | 671 | 666 | +5 | Keep root |
| `agents/api_fuzzer_agent.py` | 390 | 386 | +4 | Keep root |
| `core/logger.py` | 180 | 176 | +4 | Keep root |
| `api/main_api.py` | 354 | 351 | +3 | Keep root |
| `api/services/tool_verifier.py` | 245 | 242 | +3 | Keep root |
| `core/license_manager.py` | 293 | 296 | -3 | **Use dlnk_FINAL** |
| `core/nvd_client.py` | 81 | 78 | +3 | Keep root |
| `agents/exploit_agent.py` | 615 | 614 | +1 | Keep root |
| `ai_testing_system.py` | 607 | 608 | -1 | **Use dlnk_FINAL** |
| `cli/main.py` | 287 | 286 | +1 | Keep root |
| `core/agent_registry.py` | 95 | 96 | -1 | **Use dlnk_FINAL** |

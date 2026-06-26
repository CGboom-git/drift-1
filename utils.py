import argparse
import random
import numpy as np
import logging

def set_seed(seed):
    random.seed(seed)
    np.random.seed(seed)
    return seed

def get_logger(filename=None):
    logger = logging.getLogger('logger')
    logger.setLevel(logging.DEBUG)
    logging.basicConfig(format='%(asctime)s - %(levelname)s -   %(message)s',
                    datefmt='%m/%d/%Y %H:%M:%S',
                    level=logging.INFO)
    if filename is not None:
        handler = logging.FileHandler(filename)
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(logging.Formatter('%(asctime)s:%(levelname)s: %(message)s'))
        logging.getLogger().addHandler(handler)
    return logger

def get_args(description='DRIFT'):
    parser = argparse.ArgumentParser(description=description)
    # Eval Setting
    parser.add_argument('--benchmark_version', type=str, default='v1.2', help='the version of agentdojo')
    parser.add_argument('--model', type=str, default='gpt-4o-mini-2024-07-18', help='gpt-4o-mini, gpt-4o')
    parser.add_argument("--suites", type=str, default="banking,slack,travel,workspace", help="which suites to use, separated by comma.")
    parser.add_argument("--run_name", type=str, default=None, help="Optional results-directory name; does not change the model sent to the API.")
    parser.add_argument('--force_rerun', action='store_true', help='Whether to force rerun.')
    parser.add_argument('--do_attack', action='store_true', help='Whether the setting is under attack.')
    parser.add_argument('--attack_type', type=str, default="important_instructions", help='The attack type, you can select from "direct, ignore_previous, system_message, injecagent, dos, swearwords_dos, captcha_dos, offensive_email_dos, felony_dos, important_instructions, important_instructions_no_user_name, important_instructions_no_model_name, important_instructions_no_names, important_instructions_wrong_model_name, important_instructions_wrong_user_name, tool_knowledge"')

    parser.add_argument('--target_user_tasks', type=str, default=None, help='User task number you want to evaluate, sperated by comma, such as "1,4,7".')
    parser.add_argument('--target_injection_tasks', type=str, default=None, help='Injection task number you want to specific evaluate, sperated by comma, such as "1,2,3".')

    # DRIFT Setting
    parser.add_argument("--build_constraints", action='store_true', help="Whether to build initial constraints.")
    parser.add_argument("--injection_isolation", action='store_true', help="Whether to detect injection instruction.")
    parser.add_argument("--dynamic_validation", action='store_true', help="Whether to validate dynamically.")
    parser.add_argument("--adaptive_attack", action='store_true', help="Whether to implement adaptive attack.")

    # PACT-DRIFT settings. All are opt-in so legacy DRIFT runs remain unchanged.
    parser.add_argument("--enable_pact_drift", action="store_true", help="Enable PACT-DRIFT argument-level provenance validation.")
    parser.add_argument("--tool_contract_path", type=str, default="contracts/agentdojo_global_tool_contracts.json", help="Path to frozen global tool contracts.")
    parser.add_argument("--generate_tool_contracts", action="store_true", help="Generate tool contracts before running (prefer the offline script for full-suite contracts).")
    parser.add_argument("--freeze_tool_contract", action="store_true", help="Require runtime tool schemas to match frozen contract hashes.")
    parser.add_argument("--enable_provenance_tracking", action="store_true", help="Record runtime tool and argument provenance.")
    parser.add_argument("--enable_argument_validation", action="store_true", help="Validate ACTION arguments against provenance contracts.")
    parser.add_argument("--pact_drift_debug", action="store_true", help="Emit PACT-DRIFT debug logs.")

    # IFC-DRIFT settings. This path replaces legacy checklist parameter validation with
    # an IFC task flow contract plus runtime provenance argument-flow validation.
    parser.add_argument("--enable_ifc_drift", action="store_true", help="Enable IFC-DRIFT task flow and argument-flow validation.")
    parser.add_argument("--ifc_global_contract_path", type=str, default=None, help="Path to the reviewed IFC global contract.")
    parser.add_argument("--ifc_task_contract_model", type=str, default=None, help="Optional model label used for IFC task-flow contract generation.")
    parser.add_argument("--ifc_disable_legacy_checklist", action="store_true", help="Disable legacy DRIFT checklist validation when IFC-DRIFT is enabled.")
    parser.add_argument("--ifc_debug", action="store_true", help="Emit IFC-DRIFT debug logs.")
    parser.add_argument("--ifc_allow_action_replan", action="store_true", help="Allow out-of-trajectory ACTION calls to request a secure replan instead of hard rejection.")

    # Environment
    parser.add_argument('--seed', type=int, default=98, help='Random Seed.')


    args = parser.parse_args()
    if args.enable_ifc_drift:
        args.ifc_disable_legacy_checklist = True

    return args

#!/usr/bin/env python3
"""Generate docs/swagger.json by inspecting Janus Gateway sources."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Iterable, List, MutableMapping, Optional, Sequence, Set, Tuple


def extract_braced_block(text: str, brace_index: int) -> Tuple[str, int]:
    """Return the block contained in braces starting at brace_index."""
    depth = 0
    block_start = brace_index + 1
    for idx in range(brace_index, len(text)):
        char = text[idx]
        if char == '{':
            depth += 1
            if depth == 1:
                block_start = idx + 1
        elif char == '}':
            depth -= 1
            if depth == 0:
                return text[block_start:idx], idx
    raise ValueError("Unbalanced braces encountered while parsing source")


def get_function_body(text: str, signature: str) -> str:
    """Extract the body of the function with the given signature."""
    idx = text.find(signature)
    if idx == -1:
        raise ValueError(f"Could not locate '{signature}' in source")
    brace_index = text.find('{', idx)
    if brace_index == -1:
        raise ValueError(f"Could not find opening brace for '{signature}'")
    body, _ = extract_braced_block(text, brace_index)
    return body


def extract_block(text: str, anchor: str) -> Tuple[str, int]:
    """Extract the block starting at the given anchor inside text."""
    idx = text.find(anchor)
    if idx == -1:
        raise ValueError(f"Could not locate block anchor '{anchor}'")
    brace_index = text.find('{', idx)
    if brace_index == -1:
        raise ValueError(f"Could not find opening brace after '{anchor}'")
    block, end_index = extract_braced_block(text, brace_index)
    return block, end_index


def extract_if_else_blocks(text: str, pattern: str) -> Tuple[str, str]:
    """Return the blocks for the first if/else matching pattern."""
    idx = text.find(pattern)
    if idx == -1:
        raise ValueError(f"Could not locate if/else pattern '{pattern}'")
    brace_index = text.find('{', idx)
    if brace_index == -1:
        raise ValueError(f"Could not find if-block for pattern '{pattern}'")
    if_block, end_index = extract_braced_block(text, brace_index)
    cursor = end_index + 1
    while cursor < len(text) and text[cursor].isspace():
        cursor += 1
    if not text.startswith('else', cursor):
        raise ValueError(f"Expected else-block following pattern '{pattern}'")
    else_brace = text.find('{', cursor)
    if else_brace == -1:
        raise ValueError(f"Could not find else-block for pattern '{pattern}'")
    else_block, _ = extract_braced_block(text, else_brace)
    return if_block, else_block


def parse_message_text_commands(text: str) -> Tuple[Dict[str, int], Dict[str, int]]:
    """Return dictionaries of positive/negative message_text comparisons."""
    positives: Dict[str, int] = {}
    negatives: Dict[str, int] = {}
    pattern = re.compile(r'strcasecmp\s*\(\s*message_text\s*,\s*"([^\"]+)"\s*\)')
    for match in pattern.finditer(text):
        command = match.group(1)
        index = match.start()
        probe = index - 1
        while probe >= 0 and text[probe].isspace():
            probe -= 1
        if probe >= 0 and text[probe] == '!':
            positives.setdefault(command, index)
        else:
            negatives.setdefault(command, index)
    return positives, negatives


def find_block_for_command(text: str, command: str) -> str:
    """Locate the if/else block handling a specific command."""
    pattern = re.compile(
        r'(?:else\s+)?if\s*\([^{}]*?strcasecmp\s*\(\s*message_text\s*,\s*"' +
        re.escape(command) + r'"\s*\)[^{}]*\)'
    )
    for match in pattern.finditer(text):
        brace_index = text.find('{', match.end())
        if brace_index == -1:
            continue
        block, _ = extract_braced_block(text, brace_index)
        return block
    return ""


def classify_janus_commands(text: str, positions: Dict[str, int]) -> Tuple[List[str], List[str]]:
    """Return session-level and handle-level command lists."""
    session: List[str] = []
    handle: List[str] = []
    for command in sorted(positions):
        block = find_block_for_command(text, command)
        normalized = block.replace(' ', '')
        idx_handle_not_null = normalized.find('if(handle!=NULL')
        idx_handle_null = normalized.find('if(handle==NULL')
        if idx_handle_not_null != -1 and (idx_handle_null == -1 or idx_handle_not_null < idx_handle_null):
            session.append(command)
        elif idx_handle_null != -1:
            handle.append(command)
        else:
            session.append(command)
    return session, handle


def deduplicate_preserve_order(values: Iterable[str]) -> List[str]:
    seen = set()
    ordered: List[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered


def format_command_list(commands: Sequence[str]) -> str:
    return ', '.join(commands)


@dataclass
class ParameterEntry:
    name: str
    type_token: str
    flags: Set[str]

    @property
    def required(self) -> bool:
        return 'JANUS_JSON_PARAM_REQUIRED' in self.flags


TYPE_TOKEN_MAP = {
    'JSON_STRING': {'type': 'string'},
    'JSON_INTEGER': {'type': 'integer'},
    'JSON_REAL': {'type': 'number'},
    'JSON_OBJECT': {'type': 'object', 'additionalProperties': True},
    'JSON_ARRAY': {'type': 'array', 'items': {}},
    'JANUS_JSON_BOOL': {'type': 'boolean'},
}


def parse_flags(flags_str: Optional[str]) -> Set[str]:
    flags: Set[str] = set()
    if not flags_str:
        return flags
    cleaned = flags_str.split('/*', 1)[0]
    for token in cleaned.split('|'):
        token = token.strip()
        if not token or token == '0':
            continue
        flags.add(token)
    return flags


def parameter_entry_schema(entry: ParameterEntry) -> Dict[str, object]:
    base = TYPE_TOKEN_MAP.get(entry.type_token, {'type': 'string'})
    schema = dict(base)
    if entry.type_token == 'JSON_ARRAY' and 'items' not in schema:
        schema['items'] = {}
    if 'JANUS_JSON_PARAM_POSITIVE' in entry.flags:
        schema['minimum'] = 1
    if 'JANUS_JSON_PARAM_NONEMPTY' in entry.flags and schema.get('type') == 'string':
        schema['minLength'] = 1
    if 'JANUS_JSON_PARAM_NULLABLE' in entry.flags:
        schema['nullable'] = True
    return schema


def strip_block_comments(text: str) -> str:
    return re.sub(r'/\*.*?\*/', '', text, flags=re.S)


def parse_parameter_arrays(text: str) -> Dict[str, List[ParameterEntry]]:
    pattern = re.compile(r'static\s+struct\s+janus_json_parameter\s+(\w+)\s*\[\]\s*=\s*\{', re.MULTILINE)
    arrays: Dict[str, List[ParameterEntry]] = {}
    for match in pattern.finditer(text):
        name = match.group(1)
        brace_index = text.find('{', match.end() - 1)
        if brace_index == -1:
            continue
        block, _ = extract_braced_block(text, brace_index)
        block = strip_block_comments(block)
        entries: List[ParameterEntry] = []
        entry_pattern = re.compile(r'\{\s*"([^"\\]+)"\s*,\s*([A-Z0-9_]+)\s*(?:,\s*([^}]+?))?\}', re.MULTILINE)
        for entry_match in entry_pattern.finditer(block):
            param_name = entry_match.group(1)
            type_token = entry_match.group(2)
            flags_raw = entry_match.group(3)
            flags = parse_flags(flags_raw)
            entries.append(ParameterEntry(param_name, type_token, flags))
        arrays[name] = entries
    return arrays


def collect_command_parameters(text: str, commands: Sequence[str]) -> Dict[str, List[str]]:
    mapping: Dict[str, List[str]] = {}
    parameter_pattern = re.compile(r'JANUS_VALIDATE_JSON_OBJECT\s*\(\s*root\s*,\s*(\w+)\s*,')
    for command in commands:
        block = find_block_for_command(text, command)
        params: List[str] = []
        if block:
            for match in parameter_pattern.finditer(block):
                params.append(match.group(1))
        mapping[command] = params
    return mapping


def command_to_pascal(command: str) -> str:
    parts = re.split(r'[_\-]+', command)
    return ''.join(part.capitalize() for part in parts if part)


def merge_parameter_schemas(array_names: Sequence[str], parameter_arrays: Dict[str, List[ParameterEntry]]) -> Tuple[Dict[str, object], List[str]]:
    properties: Dict[str, object] = {}
    required: Set[str] = set()
    for array_name in array_names:
        for entry in parameter_arrays.get(array_name, []):
            properties[entry.name] = parameter_entry_schema(entry)
            if entry.required:
                required.add(entry.name)
    return properties, sorted(required)


def build_command_components(
    aggregator_name: str,
    component_prefix: str,
    base_ref: str,
    commands: Sequence[str],
    command_params: Dict[str, List[str]],
    parameter_arrays: Dict[str, List[ParameterEntry]],
    description: str,
) -> Tuple[Dict[str, object], Dict[str, object]]:
    if not commands:
        aggregator_schema = {
            'description': description,
            'allOf': [{'$ref': base_ref}],
        }
        return {}, {aggregator_name: aggregator_schema}

    command_components: Dict[str, object] = {}
    mapping: Dict[str, str] = {}
    one_of: List[Dict[str, str]] = []
    for command in commands:
        component_name = f'{component_prefix}{command_to_pascal(command)}'
        param_arrays = command_params.get(command, [])
        properties, required = merge_parameter_schemas(param_arrays, parameter_arrays)
        properties['janus'] = {'type': 'string', 'enum': [command]}
        component_schema = {
            'type': 'object',
            'allOf': [{'$ref': base_ref}],
            'properties': properties,
            'required': sorted(set(required + ['janus'])),
            'additionalProperties': True,
        }
        command_components[component_name] = component_schema
        ref = f'#/components/schemas/{component_name}'
        mapping[command] = ref
        one_of.append({'$ref': ref})

    aggregator_schema = {
        'description': description,
        'oneOf': one_of,
        'discriminator': {
            'propertyName': 'janus',
            'mapping': mapping,
        },
    }
    return command_components, {aggregator_name: aggregator_schema}

def build_spec(source_path: Path) -> MutableMapping[str, object]:
    source = source_path.read_text(encoding='utf-8')
    janus_body = get_function_body(source, 'int janus_process_incoming_request(')
    root_block, root_end = extract_block(janus_body, 'if(session_id == 0 && handle_id == 0)')
    root_pos, root_neg = parse_message_text_commands(root_block)
    janus_root_commands = deduplicate_preserve_order(sorted(set(root_pos) | set(root_neg)))

    post_root = janus_body[root_end + 1 :]
    main_pos, main_neg = parse_message_text_commands(post_root)
    for key in list(main_pos):
        if key in janus_root_commands:
            main_pos.pop(key)
    for key in list(main_neg):
        if key in janus_root_commands:
            main_neg.pop(key)
    janus_session_commands, janus_handle_commands = classify_janus_commands(post_root, main_pos)
    for key in sorted(main_neg):
        if key not in janus_session_commands and key not in janus_handle_commands:
            janus_session_commands.append(key)

    admin_body = get_function_body(source, 'int janus_process_incoming_admin_request(')
    admin_root_block, admin_root_end = extract_block(admin_body, 'if(session_id == 0 && handle_id == 0)')
    admin_root_pos, admin_root_neg = parse_message_text_commands(admin_root_block)
    admin_root_commands = deduplicate_preserve_order(sorted(set(admin_root_pos) | set(admin_root_neg)))

    admin_tail = admin_body[admin_root_end + 1 :]
    admin_session_block, admin_handle_block = extract_if_else_blocks(admin_tail, 'if(handle == NULL)')
    admin_session_pos, admin_session_neg = parse_message_text_commands(admin_session_block)
    admin_handle_pos, admin_handle_neg = parse_message_text_commands(admin_handle_block)
    admin_session_commands = deduplicate_preserve_order(sorted(set(admin_session_pos) | set(admin_session_neg)))
    admin_handle_commands = deduplicate_preserve_order(sorted(set(admin_handle_pos) | set(admin_handle_neg)))

    commands = {
        'janus': {
            'root': janus_root_commands,
            'session': deduplicate_preserve_order(janus_session_commands),
            'handle': deduplicate_preserve_order(janus_handle_commands),
        },
        'admin': {
            'root': admin_root_commands,
            'session': admin_session_commands,
            'handle': admin_handle_commands,
        },
    }

    parameter_arrays = parse_parameter_arrays(source)
    janus_root_params = collect_command_parameters(root_block, commands['janus']['root'])
    janus_session_params = collect_command_parameters(post_root, commands['janus']['session'])
    janus_handle_params = collect_command_parameters(post_root, commands['janus']['handle'])
    admin_root_params = collect_command_parameters(admin_root_block, commands['admin']['root'])
    admin_session_params = collect_command_parameters(admin_session_block, commands['admin']['session'])
    admin_handle_params = collect_command_parameters(admin_handle_block, commands['admin']['handle'])

    spec: MutableMapping[str, object] = {
        'openapi': '3.0.3',
        'info': {
            'title': 'Janus Gateway REST & Admin API',
            'description': 'OpenAPI document generated by tools/generate_swagger.py.',
            'version': '1.0.0',
            'license': {
                'name': 'GPL-3.0-or-later',
                'url': 'https://www.gnu.org/licenses/gpl-3.0.html',
            },
        },
        'tags': [
            {'name': 'Janus API', 'description': 'Core REST API exposed under /janus.'},
            {'name': 'Admin API', 'description': 'Administrative REST API exposed under /admin.'},
        ],
        'servers': [
            {'url': 'http://localhost:8088', 'description': 'HTTP transport.'},
            {'url': 'https://localhost:8089', 'description': 'HTTPS transport.'},
        ],
    }

    spec['components'] = {
        'securitySchemes': {
            'JanusQuerySecret': {
                'type': 'apiKey',
                'name': 'apisecret',
                'in': 'query',
                'description': 'API secret configured in janus.jcfg.',
            },
            'JanusQueryToken': {
                'type': 'apiKey',
                'name': 'token',
                'in': 'query',
                'description': 'Authentication token when token-based auth is enabled.',
            },
        },
        'schemas': {
            'JanusCommandBase': {
                'type': 'object',
                'required': ['janus', 'transaction'],
                'properties': {
                    'janus': {'type': 'string', 'description': 'Command identifier.'},
                    'transaction': {'type': 'string', 'description': 'Opaque client-specified transaction id.'},
                    'apisecret': {'type': 'string', 'description': 'API secret when required.'},
                    'token': {'type': 'string', 'description': 'Authentication token when required.'},
                },
                'additionalProperties': True,
            },
            'JanusSessionCommandBase': {
                'allOf': [
                    {'$ref': '#/components/schemas/JanusCommandBase'},
                    {
                        'type': 'object',
                        'properties': {
                            'session_id': {
                                'type': 'integer',
                                'minimum': 1,
                                'description': 'Optional session identifier; defaults to the URL path value.',
                            }
                        },
                    },
                ]
            },
            'JanusHandleCommandBase': {
                'allOf': [
                    {'$ref': '#/components/schemas/JanusSessionCommandBase'},
                    {
                        'type': 'object',
                        'properties': {
                            'handle_id': {
                                'type': 'integer',
                                'minimum': 1,
                                'description': 'Optional handle identifier; defaults to the URL path value.',
                            }
                        },
                    },
                ]
            },
            'AdminCommandBase': {
                'allOf': [
                    {'$ref': '#/components/schemas/JanusCommandBase'},
                    {
                        'type': 'object',
                        'properties': {
                            'admin_secret': {
                                'type': 'string',
                                'description': 'Administrative API secret when configured.',
                            }
                        },
                    },
                ]
            },
            'AdminSessionCommandBase': {
                'allOf': [
                    {'$ref': '#/components/schemas/AdminCommandBase'},
                    {
                        'type': 'object',
                        'properties': {
                            'session_id': {
                                'type': 'integer',
                                'minimum': 1,
                                'description': 'Optional session identifier; defaults to the URL path value.',
                            }
                        },
                    },
                ]
            },
            'AdminHandleCommandBase': {
                'allOf': [
                    {'$ref': '#/components/schemas/AdminSessionCommandBase'},
                    {
                        'type': 'object',
                        'properties': {
                            'handle_id': {
                                'type': 'integer',
                                'minimum': 1,
                                'description': 'Optional handle identifier; defaults to the URL path value.',
                            }
                        },
                    },
                ]
            },
        },
        'responses': {
            'JanusStandardResponse': {
                'description': 'Standard Janus response payload.',
                'content': {
                    'application/json': {
                        'schema': {'$ref': '#/components/schemas/JanusResponse'}
                    }
                },
            },
            'JanusEventResponse': {
                'description': 'Event payload(s) produced by the gateway.',
                'content': {
                    'application/json': {
                        'schema': {
                            'oneOf': [
                                {'$ref': '#/components/schemas/JanusResponse'},
                                {
                                    'type': 'array',
                                    'items': {'$ref': '#/components/schemas/JanusResponse'},
                                },
                            ]
                        }
                    }
                },
            },
            'JanusErrorResponse': {
                'description': 'Error payload returned by Janus.',
                'content': {
                    'application/json': {
                        'schema': {'$ref': '#/components/schemas/JanusError'}
                    }
                },
            },
        },
    }

    command_component_sets = [
        build_command_components(
            aggregator_name='JanusRootCommand',
            component_prefix='JanusRootCommand',
            base_ref='#/components/schemas/JanusCommandBase',
            commands=commands['janus']['root'],
            command_params=janus_root_params,
            parameter_arrays=parameter_arrays,
            description='Commands accepted at the Janus root endpoint.',
        ),
        build_command_components(
            aggregator_name='JanusSessionCommand',
            component_prefix='JanusSessionCommand',
            base_ref='#/components/schemas/JanusSessionCommandBase',
            commands=commands['janus']['session'],
            command_params=janus_session_params,
            parameter_arrays=parameter_arrays,
            description='Session-level commands on /janus/{sessionId}.',
        ),
        build_command_components(
            aggregator_name='JanusHandleCommand',
            component_prefix='JanusHandleCommand',
            base_ref='#/components/schemas/JanusHandleCommandBase',
            commands=commands['janus']['handle'],
            command_params=janus_handle_params,
            parameter_arrays=parameter_arrays,
            description='Handle-level commands on /janus/{sessionId}/{handleId}.',
        ),
        build_command_components(
            aggregator_name='AdminRootCommand',
            component_prefix='AdminRootCommand',
            base_ref='#/components/schemas/AdminCommandBase',
            commands=commands['admin']['root'],
            command_params=admin_root_params,
            parameter_arrays=parameter_arrays,
            description='Administrative commands at /admin.',
        ),
        build_command_components(
            aggregator_name='AdminSessionCommand',
            component_prefix='AdminSessionCommand',
            base_ref='#/components/schemas/AdminSessionCommandBase',
            commands=commands['admin']['session'],
            command_params=admin_session_params,
            parameter_arrays=parameter_arrays,
            description='Session-scoped administrative commands.',
        ),
        build_command_components(
            aggregator_name='AdminHandleCommand',
            component_prefix='AdminHandleCommand',
            base_ref='#/components/schemas/AdminHandleCommandBase',
            commands=commands['admin']['handle'],
            command_params=admin_handle_params,
            parameter_arrays=parameter_arrays,
            description='Handle-scoped administrative commands.',
        ),
    ]

    for command_components, aggregator in command_component_sets:
        spec['components']['schemas'].update(command_components)
        spec['components']['schemas'].update(aggregator)

    spec['components']['schemas']['JanusResponse'] = {
        'type': 'object',
        'required': ['janus'],
        'properties': {
            'janus': {'type': 'string', 'description': 'Response type.'},
            'transaction': {'type': 'string', 'description': 'Transaction identifier when available.'},
            'session_id': {'type': 'integer', 'description': 'Session identifier when applicable.'},
            'sender': {'type': 'integer', 'description': 'Handle identifier emitting the event.'},
            'opaque_id': {'type': 'string', 'description': 'Opaque identifier associated with the handle.'},
            'data': {'type': 'object', 'description': 'Generic success response payload.', 'additionalProperties': True},
            'plugindata': {'type': 'object', 'description': 'Plugin-specific payload.', 'additionalProperties': True},
            'jsep': {'type': 'object', 'description': 'Optional JSEP payload.', 'additionalProperties': True},
            'error': {
                'type': 'object',
                'properties': {
                    'code': {'type': 'integer'},
                    'reason': {'type': 'string'},
                },
                'required': ['code', 'reason'],
                'additionalProperties': False,
            },
        },
        'additionalProperties': True,
    }

    spec['components']['schemas']['JanusError'] = {
        'type': 'object',
        'required': ['janus', 'error'],
        'properties': {
            'janus': {'type': 'string', 'enum': ['error']},
            'transaction': {'type': 'string'},
            'session_id': {'type': 'integer'},
            'error': {
                'type': 'object',
                'required': ['code', 'reason'],
                'properties': {
                    'code': {'type': 'integer'},
                    'reason': {'type': 'string'},
                },
                'additionalProperties': False,
            },
        },
        'additionalProperties': True,
    }

    paths: MutableMapping[str, object] = {}

    janus_root_desc = 'Available commands: ' + format_command_list(commands['janus']['root']) + '.'
    paths['/janus'] = {
        'post': {
            'tags': ['Janus API'],
            'summary': 'Execute a Janus root command',
            'description': janus_root_desc,
            'operationId': 'postJanusRootCommand',
            'requestBody': {
                'required': True,
                'content': {
                    'application/json': {
                        'schema': {'$ref': '#/components/schemas/JanusRootCommand'}
                    }
                },
            },
            'responses': {
                '200': {'$ref': '#/components/responses/JanusStandardResponse'},
                '400': {'$ref': '#/components/responses/JanusErrorResponse'},
                '401': {'$ref': '#/components/responses/JanusErrorResponse'},
                '500': {'$ref': '#/components/responses/JanusErrorResponse'},
            },
        }
    }

    paths['/janus/info'] = {
        'get': {
            'tags': ['Janus API'],
            'summary': 'Retrieve Janus core info',
            'description': 'Shortcut for the info command.' ,
            'operationId': 'getJanusInfo',
            'responses': {
                '200': {'$ref': '#/components/responses/JanusStandardResponse'},
                '500': {'$ref': '#/components/responses/JanusErrorResponse'},
            },
        }
    }

    paths['/janus/ping'] = {
        'get': {
            'tags': ['Janus API'],
            'summary': 'Ping the Janus core',
            'description': 'Shortcut for the ping command.',
            'operationId': 'getJanusPing',
            'responses': {
                '200': {'$ref': '#/components/responses/JanusStandardResponse'},
                '500': {'$ref': '#/components/responses/JanusErrorResponse'},
            },
        }
    }

    janus_session_desc = 'Supported commands: ' + format_command_list(commands['janus']['session']) + '.'
    paths['/janus/{sessionId}'] = {
        'parameters': [
            {
                'name': 'sessionId',
                'in': 'path',
                'required': True,
                'schema': {'type': 'integer', 'minimum': 1},
                'description': 'Existing Janus session identifier.',
            }
        ],
        'get': {
            'tags': ['Janus API'],
            'summary': 'Long poll for session events',
            'description': 'Retrieves events queued for the session via long polling.',
            'operationId': 'getJanusSessionEvents',
            'parameters': [
                {
                    'name': 'maxev',
                    'in': 'query',
                    'required': False,
                    'schema': {'type': 'integer', 'minimum': 1},
                    'description': 'Maximum number of events returned in a single response.',
                },
                {
                    'name': 'apisecret',
                    'in': 'query',
                    'required': False,
                    'schema': {'type': 'string'},
                    'description': 'API secret when configured.',
                },
                {
                    'name': 'token',
                    'in': 'query',
                    'required': False,
                    'schema': {'type': 'string'},
                    'description': 'Access token when token-based auth is enabled.',
                },
            ],
            'responses': {
                '200': {'$ref': '#/components/responses/JanusEventResponse'},
                '401': {'$ref': '#/components/responses/JanusErrorResponse'},
                '404': {'$ref': '#/components/responses/JanusErrorResponse'},
                '500': {'$ref': '#/components/responses/JanusErrorResponse'},
            },
            'security': [{}, {'JanusQuerySecret': []}, {'JanusQueryToken': []}],
        },
        'post': {
            'tags': ['Janus API'],
            'summary': 'Execute a Janus session command',
            'description': janus_session_desc,
            'operationId': 'postJanusSessionCommand',
            'requestBody': {
                'required': True,
                'content': {
                    'application/json': {
                        'schema': {'$ref': '#/components/schemas/JanusSessionCommand'}
                    }
                },
            },
            'responses': {
                '200': {'$ref': '#/components/responses/JanusStandardResponse'},
                '400': {'$ref': '#/components/responses/JanusErrorResponse'},
                '401': {'$ref': '#/components/responses/JanusErrorResponse'},
                '404': {'$ref': '#/components/responses/JanusErrorResponse'},
                '500': {'$ref': '#/components/responses/JanusErrorResponse'},
            },
        },
    }

    janus_handle_desc = 'Supported handle commands: ' + format_command_list(commands['janus']['handle']) + '.'
    paths['/janus/{sessionId}/{handleId}'] = {
        'parameters': [
            {
                'name': 'sessionId',
                'in': 'path',
                'required': True,
                'schema': {'type': 'integer', 'minimum': 1},
                'description': 'Existing Janus session identifier.',
            },
            {
                'name': 'handleId',
                'in': 'path',
                'required': True,
                'schema': {'type': 'integer', 'minimum': 1},
                'description': 'Plugin handle identifier within the session.',
            },
        ],
        'post': {
            'tags': ['Janus API'],
            'summary': 'Execute a Janus handle command',
            'description': janus_handle_desc,
            'operationId': 'postJanusHandleCommand',
            'requestBody': {
                'required': True,
                'content': {
                    'application/json': {
                        'schema': {'$ref': '#/components/schemas/JanusHandleCommand'}
                    }
                },
            },
            'responses': {
                '200': {'$ref': '#/components/responses/JanusStandardResponse'},
                '400': {'$ref': '#/components/responses/JanusErrorResponse'},
                '401': {'$ref': '#/components/responses/JanusErrorResponse'},
                '404': {'$ref': '#/components/responses/JanusErrorResponse'},
                '500': {'$ref': '#/components/responses/JanusErrorResponse'},
            },
        },
    }

    admin_root_desc = 'Available admin commands: ' + format_command_list(commands['admin']['root']) + '.'
    paths['/admin'] = {
        'post': {
            'tags': ['Admin API'],
            'summary': 'Execute an admin command',
            'description': admin_root_desc,
            'operationId': 'postAdminRootCommand',
            'requestBody': {
                'required': True,
                'content': {
                    'application/json': {
                        'schema': {'$ref': '#/components/schemas/AdminRootCommand'}
                    }
                },
            },
            'responses': {
                '200': {'$ref': '#/components/responses/JanusStandardResponse'},
                '400': {'$ref': '#/components/responses/JanusErrorResponse'},
                '401': {'$ref': '#/components/responses/JanusErrorResponse'},
                '500': {'$ref': '#/components/responses/JanusErrorResponse'},
            },
        }
    }

    paths['/admin/info'] = {
        'get': {
            'tags': ['Admin API'],
            'summary': 'Retrieve Janus info via admin endpoint',
            'description': 'Administrative shortcut for the info command.',
            'operationId': 'getAdminInfo',
            'responses': {
                '200': {'$ref': '#/components/responses/JanusStandardResponse'},
                '500': {'$ref': '#/components/responses/JanusErrorResponse'},
            },
        }
    }

    paths['/admin/ping'] = {
        'get': {
            'tags': ['Admin API'],
            'summary': 'Ping the Janus admin interface',
            'description': 'Administrative shortcut for the ping command.',
            'operationId': 'getAdminPing',
            'responses': {
                '200': {'$ref': '#/components/responses/JanusStandardResponse'},
                '500': {'$ref': '#/components/responses/JanusErrorResponse'},
            },
        }
    }

    admin_session_desc = 'Session-scoped admin commands: ' + format_command_list(commands['admin']['session']) + '.'
    paths['/admin/{sessionId}'] = {
        'parameters': [
            {
                'name': 'sessionId',
                'in': 'path',
                'required': True,
                'schema': {'type': 'integer', 'minimum': 1},
                'description': 'Target Janus session identifier.',
            }
        ],
        'post': {
            'tags': ['Admin API'],
            'summary': 'Execute a session-scoped admin command',
            'description': admin_session_desc,
            'operationId': 'postAdminSessionCommand',
            'requestBody': {
                'required': True,
                'content': {
                    'application/json': {
                        'schema': {'$ref': '#/components/schemas/AdminSessionCommand'}
                    }
                },
            },
            'responses': {
                '200': {'$ref': '#/components/responses/JanusStandardResponse'},
                '400': {'$ref': '#/components/responses/JanusErrorResponse'},
                '401': {'$ref': '#/components/responses/JanusErrorResponse'},
                '404': {'$ref': '#/components/responses/JanusErrorResponse'},
                '500': {'$ref': '#/components/responses/JanusErrorResponse'},
            },
        },
    }

    admin_handle_desc = 'Handle-scoped admin commands: ' + format_command_list(commands['admin']['handle']) + '.'
    paths['/admin/{sessionId}/{handleId}'] = {
        'parameters': [
            {
                'name': 'sessionId',
                'in': 'path',
                'required': True,
                'schema': {'type': 'integer', 'minimum': 1},
                'description': 'Target Janus session identifier.',
            },
            {
                'name': 'handleId',
                'in': 'path',
                'required': True,
                'schema': {'type': 'integer', 'minimum': 1},
                'description': 'Target plugin handle identifier.',
            },
        ],
        'post': {
            'tags': ['Admin API'],
            'summary': 'Execute a handle-scoped admin command',
            'description': admin_handle_desc,
            'operationId': 'postAdminHandleCommand',
            'requestBody': {
                'required': True,
                'content': {
                    'application/json': {
                        'schema': {'$ref': '#/components/schemas/AdminHandleCommand'}
                    }
                },
            },
            'responses': {
                '200': {'$ref': '#/components/responses/JanusStandardResponse'},
                '400': {'$ref': '#/components/responses/JanusErrorResponse'},
                '401': {'$ref': '#/components/responses/JanusErrorResponse'},
                '404': {'$ref': '#/components/responses/JanusErrorResponse'},
                '500': {'$ref': '#/components/responses/JanusErrorResponse'},
            },
        },
    }

    spec['paths'] = paths
    return spec


SWAGGER_UI_TEMPLATE = """<!DOCTYPE html>
<html lang=\"en\">
  <head>
    <meta charset=\"utf-8\" />
    <title>Janus Gateway API</title>
    <link rel=\"stylesheet\" href=\"https://unpkg.com/swagger-ui-dist@5/swagger-ui.css\" />
    <style>body { margin: 0; }</style>
  </head>
  <body>
    <div id=\"swagger-ui\"></div>
    <script src=\"https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js\"></script>
    <script>
      window.addEventListener('load', function () {
        window.ui = SwaggerUIBundle({
          url: '/swagger.json',
          dom_id: '#swagger-ui',
          presets: [SwaggerUIBundle.presets.apis],
        });
      });
    </script>
  </body>
</html>
"""


def serve_spec(rendered: str, host: str, port: int) -> None:
    spec_bytes = rendered.encode('utf-8')

    class SwaggerHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # type: ignore[override]
            if self.path in ('/', '/index.html'):
                body = SWAGGER_UI_TEMPLATE.encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path == '/swagger.json':
                self.send_response(200)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self.send_header('Content-Length', str(len(spec_bytes)))
                self.end_headers()
                self.wfile.write(spec_bytes)
                return
            self.send_response(404)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.end_headers()
            self.wfile.write(b'Not found')

        def log_message(self, format: str, *args: object) -> None:  # type: ignore[override]
            return

    server = ThreadingHTTPServer((host, port), SwaggerHandler)
    address = f'http://{host}:{port}/'
    print(f'Serving Swagger UI at {address} (Ctrl+C to stop)')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nShutting down Swagger UI server...')
    finally:
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description='Generate docs/swagger.json from Janus sources.')
    parser.add_argument('--source', default='src/janus.c', help='Path to janus.c relative to repository root.')
    parser.add_argument('--output', default='docs/swagger.json', help='Output path for the generated OpenAPI document.')
    parser.add_argument('--stdout', action='store_true', help='Print the generated document to stdout instead of writing the file.')
    parser.add_argument('--check', action='store_true', help='Exit with status 1 if the output would change.')
    parser.add_argument('--serve', action='store_true', help='Start a Swagger UI dev server for the generated document.')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind when using --serve (default: 127.0.0.1).')
    parser.add_argument('--port', type=int, default=8000, help='Port to bind when using --serve (default: 8000).')
    parser.add_argument('--no-write', action='store_true', help='Skip writing the output file (useful with --serve).')
    args = parser.parse_args()

    if args.check and args.serve:
        parser.error('--check cannot be combined with --serve')

    repo_root = Path(__file__).resolve().parents[1]
    source_path = (repo_root / args.source).resolve()
    output_path = (repo_root / args.output).resolve()

    spec = build_spec(source_path)
    rendered = json.dumps(spec, indent=2, sort_keys=False) + '\n'

    if args.check:
        if not output_path.exists():
            raise SystemExit(1)
        current = output_path.read_text(encoding='utf-8')
        raise SystemExit(0 if current == rendered else 1)

    if args.stdout:
        print(rendered, end='')

    should_write = not args.no_write and (not args.stdout or args.serve)
    if should_write:
        output_path.write_text(rendered, encoding='utf-8')

    if args.serve:
        serve_spec(rendered, args.host, args.port)


if __name__ == '__main__':
    main()

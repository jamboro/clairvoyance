import requests

import re
import logging
from typing import Any
from typing import Set
from typing import List
from typing import Dict
from typing import Optional
from enum import Enum
from clairvoyance import graphql

class object_enum(Enum):
    QUERY = 0
    FIELD = 1,
    TYPE = 2,
    ARG = 3,
    INPUT_FIELD = 4


def parse_errors(error_message:str):
    generic_match_regex = r'[\'"]?[_A-Za-z\[\]!]+[_0-9a-zA-Z\[\]!]*[\'"]'
    error_message = error_message.upper()

    suggestions_txt_replace = [fr'DID YOU MEAN TO USE AN INLINE FRAGMENT ON '
                         fr'DID YOU MEAN ']

    field_regex = [fr'ON FIELD {generic_match_regex}',
                   fr'FIELD {generic_match_regex}',
                   fr'REQUIRES BOTH {generic_match_regex} AND {generic_match_regex}'
                   ]

    types_regex = [fr'ON TYPE {generic_match_regex}',
                   fr'OF TYPE {generic_match_regex}',
                   fr'EXPECTED TYPE {generic_match_regex}',
                   fr"OF REQUIRED TYPE {generic_match_regex} WAS NOT PROVIDED."]

    argument_re = [
        fr'ARGUMENT {generic_match_regex}'
    ]

    object_dict = {}

    #parse suggestions
    if 'DID YOU MEAN' in error_message:
        error_parsed = error_message[error_message.index('DID YOU MEAN')+len('DID YOU MEAN'):]
        suggestion_match = re.match(generic_match_regex,error_parsed)
        # all suggestions...
    elif 'REQUIRES BOTH' in error_message:
        error_parsed = error_message[error_message.index('REQUIRES BOTH')+len('REQUIRES BOTH'):]
        suggestion_match = re.match(generic_match_regex,error_parsed)

    # parse field
    if 'FIELD' in error_message:
        negative=False
        if 'CANNOT QUERY FIELD' in error_message:
            negative=True
        for f in field_regex:
            field_match = re.match(f,error_message)

    # parse types
    if 'ON TYPE' in error_message or ('OF TYPE' in error_message) or 'SINCE TYPE' in error_message or ('OF REQUIRED TYPE' in error_message):
        for t in types_regex:
            type_match = re.match(t, error_message)

    if 'ARGUMENT' in error_message:
        negative = False
        if 'UNKNOWN ARGUMENT' in error_message:
            negative = True
        for a in argument_re:
            argment_match = re.match(a,error_message)


    matched_objects = []
    if re.fullmatch(no_fields_regex, error_message):
        return []

    for regex in suggestion_regexes:
        match = re.match(regex, error_message)
        if match:
            error_parsed = error_message.replace(match.group(), '')
            error_parsed = error_parsed.replace(' or', ',').replace('"', '').replace('"', '').replace('?', '').replace(
                ',,', ',')
            splits = [m.strip() for m in error_parsed.split(',')]
            for m in splits:
                matched_objects.append(m)
                matched = True
            break

    elif context == "InputValue":
        for regex in arg_skip_regexes:
            if re.fullmatch(regex, error_message):
                return None




def probe_valid_fields(
    wordlist: Set, config: graphql.Config, input_document: str
) -> Set[str]:
    # We're assuming all fields from wordlist are valid,
    # then remove fields that produce an error message
    valid_fields = set(wordlist)

    for i in range(0, len(wordlist), config.bucket_size):
        bucket = wordlist[i: i + config.bucket_size]

        document = input_document.replace("FUZZ", " ".join(bucket))

        response = graphql.post(
            config.url,
            headers=config.headers,
            json={"query": document},
            verify=config.verify,
        )
        errors = response.json()["errors"]
        logging.debug(
            f"Sent {len(bucket)} fields, recieved {len(errors)} errors in {response.elapsed.total_seconds()} seconds"
        )

        for error in errors:
            error_message = error["message"]

            if (
                "must not have a selection since type" in error_message
                and "has no subfields" in error_message
            ):
                return set()

            # First remove field if it produced an "Cannot query field" error
            match = re.search(
                'Cannot query field [\'"](?P<invalid_field>[_A-Za-z][_0-9A-Za-z]*)[\'"]',
                error_message,
            )
            if match:
                valid_fields.discard(match.group("invalid_field"))

            # Second obtain field suggestions from error message
            valid_fields |= parse_errors(object_enum.FIELD,error_message)

    return valid_fields


def probe_valid_args(
    field: str, wordlist: Set, config: graphql.Config, input_document: str
) -> Set[str]:
    valid_args = set(wordlist)

    document = input_document.replace(
        "FUZZ", f"{field}({', '.join([w + ': 7' for w in wordlist])})"
    )

    response = graphql.post(
        config.url,
        headers=config.headers,
        json={"query": document},
        verify=config.verify,
    )
    errors = response.json()["errors"]

    for error in errors:
        error_message = error["message"]

        if (
            "must not have a selection since type" in error_message
            and "has no subfields" in error_message
        ):
            return set()

        # First remove arg if it produced an "Unknown argument" error
        match = re.search(
            'Unknown argument [\'"](?P<invalid_arg>[_A-Za-z][_0-9A-Za-z]*)[\'"] on field [\'"][_A-Za-z][_0-9A-Za-z.]*[\'"]',
            error_message,
        )
        if match:
            valid_args.discard(match.group("invalid_arg"))

        duplicate_arg_regex = 'There can be only one argument named [\"](?P<arg>[_0-9a-zA-Z\[\]!]*)[\"]\.?'
        if re.fullmatch(duplicate_arg_regex, error_message):
            match = re.fullmatch(duplicate_arg_regex, error_message)
            valid_args.discard(match.group("arg"))
            continue

        # Second obtain args suggestions from error message
        valid_args |= parse_errors(object_enum.ARG,error_message)
        if not valid_args:
            logging.warning(f"Unknown error message: {error_message}")

    return valid_args


def probe_args(
    field: str, wordlist: Set, config: graphql.Config, input_document: str
) -> Set[str]:
    valid_args = set()

    for i in range(0, len(wordlist), config.bucket_size):
        bucket = wordlist[i: i + config.bucket_size]
        valid_args |= probe_valid_args(field, bucket, config, input_document)

    return valid_args



def probe_input_fields(
    field: str, argument: str, wordlist: Set, config: graphql.Config
) -> Set[str]:
    valid_input_fields = set(wordlist)

    document = f"mutation {{ {field}({argument}: {{ {', '.join([w + ': 7' for w in wordlist])} }}) }}"

    response = graphql.post(
        config.url,
        headers=config.headers,
        json={"query": document},
        verify=config.verify,
    )
    errors = response.json()["errors"]

    for error in errors:
        error_message = error["message"]

        # First remove field if it produced an error
        match = re.search(
            'Field [\'"](?P<invalid_field>[_0-9a-zA-Z\[\]!]*)[\'"] is not defined by type [_0-9a-zA-Z\[\]!]*.',
            error_message,
        )
        if match:
            valid_input_fields.discard(match.group("invalid_field"))

        # Second obtain field suggestions from error message
        valid_input_fields |= parse_errors(object_enum.INPUT_FIELD,error_message)

    return valid_input_fields


def get_typeref(error_message: str, context: str) -> Optional[graphql.TypeRef]:
    typeref = None

    matches = parse_errors(object_enum.TYPE,error_message)

    # we only get 1 typeRef at a time?
    if any(matches):
        tk = matches[0]

        name = tk.replace("!", "").replace("[", "").replace("]", "")

        if name.endswith("Input"):
            kind = "INPUT_OBJECT"
        elif name in ["Int", "Float", "String", "Boolean", "ID"]:
            kind = "SCALAR"
        else:
            kind = "OBJECT"

        is_list = True if "[" and "]" in tk else False
        non_null_item = True if is_list and "!]" in tk else False
        non_null = True if tk.endswith("!") else False

        typeref = graphql.TypeRef(
            name=name,
            kind=kind,
            is_list=is_list,
            non_null_item=non_null_item,
            non_null=non_null,
        )

    return typeref


def probe_typeref(
    documents: List[str], context: str, config: graphql.Config
) -> Optional[graphql.TypeRef]:
    typeref = None

    for document in documents:
        response = graphql.post(
            config.url,
            headers=config.headers,
            json={"query": document},
            verify=config.verify,
        )
        errors = response.json().get("errors", [])

        for error in errors:
            typeref = get_typeref(error["message"], context)
            logging.debug(f"get_typeref('{error['message']}', '{context}') -> {typeref}")
            if typeref:
                return typeref

    if not typeref and context != 'InputValue':
        raise Exception(f"Unable to get TypeRef for {documents} in context {context}")

    return None


def probe_field_type(
        field: str, config: graphql.Config, input_document: str
) -> graphql.TypeRef:
    documents = [
        input_document.replace("FUZZ", f"{field}"),
        input_document.replace("FUZZ", f"{field} {{ lol }}"),
    ]

    typeref = probe_typeref(documents, "Field", config)
    return typeref


def probe_arg_typeref(
    field: str, arg: str, config: graphql.Config, input_document: str
) -> graphql.TypeRef:
    documents = [
        input_document.replace("FUZZ", f"{field}({arg}: 7)"),
        input_document.replace("FUZZ", f"{field}({arg}: {{}})"),
        input_document.replace("FUZZ", f"{field}({arg[:-1]}: 7)"),
        input_document.replace("FUZZ", f"{field}({arg}: \"7\")"),
        input_document.replace("FUZZ", f"{field}({arg}: false)"),
    ]

    typeref = probe_typeref(documents, "InputValue", config)
    return typeref


def probe_typename(input_document: str, config: graphql.Config) -> str:
    typename = ""
    wrong_field = "imwrongfield"
    document = input_document.replace("FUZZ", wrong_field)

    response = graphql.post(
        config.url,
        headers=config.headers,
        json={"query": document},
        verify=config.verify,
    )
    errors = response.json()["errors"]

    wrong_field_regexes = [
        f'Cannot query field [\'"]{wrong_field}[\'"] on type [\'"](?P<typename>[_0-9a-zA-Z\[\]!]*)[\'"].',
        f'Field [\'"][_0-9a-zA-Z\[\]!]*[\'"] must not have a selection since type [\'"](?P<typename>[_A-Za-z\[\]!][_0-9a-zA-Z\[\]!]*)[\'"] has no subfields.',
        f'Cannot query field [\'"]{wrong_field}[\'"] on type [\'"](?P<typename>[_0-9a-zA-Z\[\]!]*)[\'"]. Did you mean [\'"][_0-9a-zA-Z\[\]!]*[\'"]\?'
    ]

    match = None

    for regex in wrong_field_regexes:
        for error in errors:
            match = re.fullmatch(regex, error["message"])
            if match:
                break
        if match:
            break

    if not match:
        raise Exception(f"Expected '{errors}' to match any of '{wrong_field_regexes}'.")

    typename = (
        match.group("typename").replace("[", "").replace("]", "").replace("!", "")
    )

    return typename


def fetch_root_typenames(config: graphql.Config) -> Dict[str, Optional[str]]:
    documents = {
        "queryType": "query { __typename }",
        "mutationType": "mutation { __typename }",
        "subscriptionType": "subscription { __typename }",
    }
    typenames = {
        "queryType": None,
        "mutationType": None,
        "subscriptionType": None,
    }

    for name, document in documents.items():
        response = graphql.post(
            config.url,
            headers=config.headers,
            json={"query": document},
            verify=config.verify,
        )
        data = response.json().get("data", {})

        if data:
            typenames[name] = data["__typename"]

    logging.debug(f"Root typenames are: {typenames}")

    return typenames


def clairvoyance(
    wordlist: List[str],
    config: graphql.Config,
    input_schema: Dict[str, Any] = None,
    input_document: str = None,
) -> Dict[str, Any]:
    if not input_schema:
        root_typenames = fetch_root_typenames(config)
        schema = graphql.Schema(
            queryType=root_typenames["queryType"],
            mutationType=root_typenames["mutationType"],
            subscriptionType=root_typenames["subscriptionType"],
        )
    else:
        schema = graphql.Schema(schema=input_schema)

    typename = probe_typename(input_document, config)
    logging.debug(f"__typename = {typename}")

    valid_mutation_fields = probe_valid_fields(wordlist, config, input_document)
    logging.debug(f"{typename}.fields = {valid_mutation_fields}")

    for field_name in valid_mutation_fields:
        typeref = probe_field_type(field_name, config, input_document)
        field = graphql.Field(field_name, typeref)

        if field.type.name not in ["Int", "Float", "String", "Boolean", "ID"]:
            arg_names = probe_args(field.name, wordlist, config, input_document)
            logging.debug(f"{typename}.{field_name}.args = {arg_names}")
            for arg_name in arg_names:
                arg_typeref = probe_arg_typeref(
                    field.name, arg_name, config, input_document
                )
                if not arg_typeref:
                    logging.warning(f'Skip argument {arg_name} because TypeRef equals {arg_typeref}')
                    continue
                arg = graphql.InputValue(arg_name, arg_typeref)

                field.args.append(arg)
                schema.add_type(arg.type.name, "INPUT_OBJECT")
        else:
            logging.debug(
                f"Skip probe_args() for '{field.name}' of type '{field.type.name}'"
            )

        schema.types[typename].fields.append(field)
        schema.add_type(field.type.name, "OBJECT")

    return schema.to_json()

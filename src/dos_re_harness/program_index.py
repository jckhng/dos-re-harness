"""Convert static discovery to mapped-only recovery inventory without guessing extents."""
from __future__ import annotations

from pathlib import Path
import json
import os
import re

from .evidence import sha256_file


def mapped_inventory(index_path: Path, image: Path, destination: Path) -> dict:
    document = json.loads(index_path.read_text(encoding='utf-8-sig'))
    if not isinstance(document,dict) or type(document.get('format_version')) is not int or document['format_version'] != 1:
        raise ValueError('unsupported program-index version')
    if not isinstance(document.get('program'),dict) or not isinstance(document.get('functions'),list):
        raise ValueError('program-index requires program and functions')
    digest = document['program'].get('executable_sha256','')
    if not isinstance(digest,str) or not re.fullmatch('[0-9a-fA-F]{64}',digest) or sha256_file(image) != digest.lower():
        raise ValueError('imported image differs from program-index identity')
    size = image.stat().st_size
    if size == 0:
        raise ValueError('empty imported image')
    binding = dict(path=os.path.relpath(image.resolve(),destination.parent.resolve()),sha256=digest.lower())
    evidence = dict(path=os.path.relpath(index_path.resolve(),destination.parent.resolve()),sha256=sha256_file(index_path))
    units, seen = [], set()
    for function in document['functions']:
        if not isinstance(function,dict) or not isinstance(function.get('id'),str) or not function['id'] or function['id'] in seen:
            raise ValueError('function identities must be nonempty and unique')
        if not isinstance(function.get('entry'),dict) or not isinstance(function.get('name'),str):
            raise ValueError('function entry and name required')
        seen.add(function['id'])
        units.append(dict(id=function['id'],kind='function',space='imported-image',ranges=[],
            extent_complete=False,recovery='unrecovered',integrated=False,
            implementation=[],evidence=[evidence],
            notes='Mapped '+function['name']+' at '+json.dumps(function['entry'],sort_keys=True)+
                  '; analysis body is not a reviewed file extent or recovered implementation.'))
    return dict(format_version=1,id='program-index:'+digest.lower(),specimen=binding,inventory_complete=False,
        scope_description='Pinned Ghidra imported image; file/relocated/runtime address mapping and pristine-specimen lineage require target review.',
        spaces=[dict(id='imported-image',size=size,artifact=binding,description='Imported file bytes; no runtime extent conversion inferred')],
        regions=[dict(id='unclassified',space='imported-image',start=0,end=size,kind='unknown',reason='Static index does not classify file bytes')],
        units=units,verification=[],milestones=[],notes='Mapped-only discovery. Zero reconstruction/validation credit; aliases and function discovery remain incomplete.')


def command_program_index(args) -> int:
    inventory = mapped_inventory(args.index,args.image,args.inventory_out)
    with args.inventory_out.open('x',encoding='utf-8') as stream:
        json.dump(inventory,stream,indent=2)
        stream.write('\n')
    print(json.dumps(dict(mapped_functions=len(inventory['units']),inventory_complete=False,reconstruction_credit=0)))
    return 0

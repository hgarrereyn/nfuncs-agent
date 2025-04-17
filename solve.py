
import sys
sys.path.append('/Applications/Binary Ninja.app/Contents/Resources/python')
import binaryninja as bn

import json
from pydantic import BaseModel
import re
from typing import Optional
import time
from datetime import datetime
from agent import run_agent
from binja_tool import set_bv


MAX_ATTEMPTS = 40

orig = bytearray(open('./nfuncs.exe', 'rb').read())
dat = bytearray(open('./nfuncs.exe', 'rb').read())
offset = 0x140000c00

def is_valid(hlil):
    if 'VirtualProtect' in hlil:
        return True
    if hlil.count('_read') > 7:
        return True
    return True

def unpatch(start, size, key, key_size):
    for i in range(size):
        dat[start+i-offset] ^= (key >> (8 * (i % key_size))) & 0xff

def patch_region(addr, size, key, key_size):
    region = bytearray(dat[addr-offset:addr-offset+size])
    for i in range(size):
        region[i] ^= (key >> (8 * (i % key_size))) & 0xff
    return region


class Patch(BaseModel):
    addr: int
    size: int
    user: int
    key: int
    key_size: int

class PatchList(BaseModel):
    patches: list[Patch]

patches = PatchList(patches=[
    Patch(addr=0x140001510, size=0xdaf0, user=0, key=0x918fe64752f3f1bd, key_size=8),
])

# patches = PatchList.model_validate_json(open('patches.json').read())
print('Loaded', len(patches.patches), 'patches')


class Attempt(BaseModel):
    timestamp: int
    user_input: Optional[int]
    xor_key: Optional[int]
    key_size: Optional[int]
    success: bool

class AttemptList(BaseModel):
    attempts: list[Attempt]

attempts = AttemptList(attempts=[])


def parse_int(s):
    try:
        if s is None:
            return None
        if s.startswith('0x') or len(set('abcdefABCDEF') & set(s)) > 0:
            return int(s[2:], 16)
        return int(s)
    except:
        return None


print('Applying existing patches...')
for patch in patches.patches:
    unpatch(patch.addr, patch.size, patch.key, patch.key_size)

open('./nfuncs-patched.exe', 'wb').write(dat)

print('Loading patched binary...')
bv = bn.load('./nfuncs-patched.exe', options={
    'analysis.linearSweep.autorun': False,
    'analysis.limits.minStringLength': 20
})
set_bv(bv)

bv.update_analysis_and_wait()

print('Ready!')

def extract_virtualprotect_args(text):
    pattern = r'VirtualProtect\(sub_([0-9a-fA-F]+),\s*(0x[0-9a-fA-F]+)'
    match = re.search(pattern, text)
    if match:
        return int(match.group(1), 16), int(match.group(2), 16)
    return None

def render_mlil(mlil):
    ix = list(mlil.instructions)

    out = ''
    for i in ix:
        v = ':'.join(repr(i).split(':')[1:])[:-1]
        out += f'0x{i.address:x} : {v}\n'

    return out

def get_hlil(bv, func):
    current_hlil = str(bv.get_function_at(func).hlil)

    # Extract data variables
    data_extra = ''
    data = re.findall(r'data_([0-9a-fA-F]+)', current_hlil)
    if len(data) > 0:
        print('Data variables:', data)
        data_vars = [int(x, 16) for x in data]
        print(data_vars)

        # Extract from memory
        contents = bv.read(data_vars[0], 8)
        print(contents)
        data_extra += f'Data @ {data_vars[0]:x}: {contents.hex()}\n'

    if len(data_extra) > 0:
        current_hlil += '\n' + data_extra

    return current_hlil

current_func = patches.patches[-1].addr

while True:
    print(f'Current function: 0x{current_func:x}')

    current_hlil = get_hlil(bv, current_func)
    current_mlil = render_mlil(bv.get_function_at(current_func).mlil)

    print('-' * 100)
    print(current_hlil)
    print('-' * 100)

    next_func, size = extract_virtualprotect_args(current_hlil)


    solved = False
    for attempt in range(MAX_ATTEMPTS):
        print(f'Attempt {attempt+1} of {MAX_ATTEMPTS}')

        try:
            result = run_agent(current_hlil, current_mlil)
        except Exception as e:
            print(e)
            continue

        user_input = parse_int(result.get('user_input'))
        xor_key = parse_int(result.get('xor_key'))
        key_size = result.get('key_size', 8)

        attempt = Attempt(timestamp=int(datetime.now().timestamp()), user_input=user_input, xor_key=xor_key, key_size=key_size, success=False)
        
        if user_input is None or xor_key is None:
            print('Failed to produce results')
            attempts.attempts.append(attempt)
            with open('attempts.json', 'w') as f:
                json.dump(attempts.model_dump(), f, indent=2)
            continue

        print(f'Trying XOR key: 0x{xor_key:x} for function 0x{next_func:x} ({size} bytes) {key_size} bytes')
        p = Patch(addr=next_func, size=size, user=user_input, key=xor_key, key_size=key_size)
        print(p.model_dump_json())

        region = patch_region(next_func, size, xor_key, key_size)
        print(region[:10].hex())

        print('Writing patched region...')
        bv.write(next_func, region)

        bv.get_function_at(next_func).reanalyze()
        time.sleep(2) # wait for analysis to complete

        new_hlil = str(bv.get_function_at(next_func).hlil)
        print(new_hlil)

        if 'VirtualProtect' in new_hlil:
            print('Success!')
            solved = True
            attempt.success = True
            attempts.attempts.append(attempt)
            with open('attempts.json', 'w') as f:
                json.dump(attempts.model_dump(), f, indent=2)
            break
        else:
            print('Key incorrect, trying again...')
            attempt.success = False
            attempts.attempts.append(attempt)
            with open('attempts.json', 'w') as f:
                json.dump(attempts.model_dump(), f, indent=2)

    if not solved:
        print('Failed to solve')
        break

    print('Success!')

    patches.patches.append(Patch(addr=next_func, size=size, user=user_input, key=xor_key, key_size=key_size))
    with open('patches.json', 'w') as f:
        json.dump(patches.model_dump(), f, indent=2)

    current_func = next_func

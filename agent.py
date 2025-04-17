
from pydantic import BaseModel
from langchain_openai import ChatOpenAI
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.tools import tool
import operator
from typing import Optional, Annotated, Literal
from pydantic import BaseModel, Field
from langgraph.prebuilt import ToolNode
from langgraph.graph import END
from langchain_core.messages import HumanMessage, ToolMessage, SystemMessage
from langgraph.graph import StateGraph
import re

from python_tool import run_python
from binja_tool import lookup_function


def new_llm():
    return ChatOpenAI(model="o3-mini", temperature=1)

import dotenv
dotenv.load_dotenv()

class Colors:
    """ ANSI color codes """
    BLACK = "\033[0;30m"
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    BROWN = "\033[0;33m"
    BLUE = "\033[0;34m"
    PURPLE = "\033[0;35m"
    CYAN = "\033[0;36m"
    LIGHT_GRAY = "\033[0;37m"
    DARK_GRAY = "\033[1;30m"
    LIGHT_RED = "\033[1;31m"
    LIGHT_GREEN = "\033[1;32m"
    YELLOW = "\033[1;33m"
    LIGHT_BLUE = "\033[1;34m"
    LIGHT_PURPLE = "\033[1;35m"
    LIGHT_CYAN = "\033[1;36m"
    LIGHT_WHITE = "\033[1;37m"
    BOLD = "\033[1m"
    FAINT = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    NEGATIVE = "\033[7m"
    CROSSED = "\033[9m"
    END = "\033[0m"


class AgentState(BaseModel):
    code: str
    mlil: str
    messages: Annotated[list, operator.add] = []
    attempts: int = 5

    user_input: Optional[str] = None
    xor_key: Optional[str] = None
    key_size: Optional[int] = None
    summary: Optional[str] = None


PROMPT1 = """
You are an expert CTF player.
Your task is to understand a function in a decompiled binary for a CTF challenge.

The function consists of two steps:
1. 8-bytes of user input are read into a buffer and treated as a 64-bit little-endian integer.
2. This integer is manipulated in a series of arithmetic operations, to produce an XOR key.
3. The XOR key is used to deobfuscate another part of memory.

For now, work on the first step:
1. Identify the `_read` calls to find where the user input is read into a buffer.
2. There should be 8 bytes read, but the buffer is treated as a single 64-bit little-endian integer.
3. Determine the correct user input (as a 64-bit integer).

You have access to the `run_python` tool, which executes a python notebook cell and returns the output.
Do not attempt to perform any calculations yourself, let the `run_python` tool do that.
Do not perform any kind of brute force search, the validation is quite simple, just figure out how to recover the user input directly.

Each byte of the user input should be constrained to a specific value.
If the partial condition is (x == <value>) or (x != <value>), then that byte should be <value>.
You can perform a search if you need to, but check each byte individually on the partial condition.

When you have identified the correct user input, run the `UserInput` tool to submit your answer.
Provide the user input as a little-endian hex integer with the 0x prefix.

[CODE]
{code}
[/CODE]
"""

PROMPT2 = """
Now that you have identified the correct user input, you need to determine the XOR key.

The XOR key will be used in the loop after the VirtualProtect call.

Work step by step:
1. Analyze the code to identify how the user input is used to calculate the XOR key.
2. Carefully examine the logic and translate it to equivalent python code 1 to 1.
3. Use the `run_python` tool to run the python code and calculate the XOR key.

If there are any helper functions, be careful to keep track how the function arguments and return values are used.

When you have identified the correct XOR key, run the `XORKey` tool to submit your answer.
Provide the XOR key as a little-endian hex integer with the 0x prefix.
Also return the key_size (number of bytes) as an integer.
Check the & condition inside the unpacking loop to determine how many bytes are used.

If it is helpful, here is the same code represented in MLIL.
Make sure to pay attention to the number and order of arithmetic operations.

[MLIL]
{mlil}
[/MLIL]
"""


class UserInput(BaseModel):
    user_input: str = Field(description="The user input as a 64-bit integer.")

class XORKey(BaseModel):
    xor_key: str = Field(description="The XOR key used to xor the region of memory.")
    key_size: int = Field(description="The number of bytes used in the XOR key.")


def initialize(state: AgentState) -> dict:

    matches = re.findall(r'(sub_[0-9a-z]+)\(.+\)', state.code)
    
    aux = ''
    for m in matches:
        code = lookup_function(m)
        if code is None:
            continue
        aux += f'[HELPER_FUNCTION {m}]\n{code}\n[/HELPER_FUNCTION]\n'

    return {
        'messages': [HumanMessage(content=PROMPT1.format(code=state.code) + '\n\n' + aux)]
    }

def act1(state: AgentState) -> AgentState:
    llm = new_llm().bind_tools(
        [run_python, UserInput],
        # parallel_tool_calls=False,
        tool_choice="required",
        strict=True
    )
    response = llm.invoke(state.messages)
    if response.content is not None:
        print(f'[{Colors.BOLD}{Colors.GREEN}Part 1{Colors.END}] {response.content}')
    return {
        'messages': [response],
        'attempts': state.attempts - 1
    }

def found_user_input(state: AgentState) -> dict:
    user_input = state.messages[-1].tool_calls[0]['args']['user_input']
    print(f'[{Colors.BOLD}{Colors.GREEN}USER_INPUT{Colors.END}] {user_input}')

    return {
        'messages': [
            ToolMessage(content='Ack', tool_call_id=state.messages[-1].tool_calls[0]['id']),
            HumanMessage(content=PROMPT2.format(mlil=state.mlil))
        ],
        'user_input': user_input,
        'attempts': 3
    }

def parse_int(s):
    try:
        if s is None:
            return None
        if s.startswith('0x') or len(set('abcdefABCDEF') & set(s)) > 0:
            return int(s[2:], 16)
        return int(s)
    except:
        return None

def act2(state: AgentState) -> AgentState:
    llm = new_llm().bind_tools(
        [run_python, XORKey],
        # parallel_tool_calls=False,
        tool_choice="required",
        strict=True
    )
    response = llm.invoke(state.messages)
    if response.content is not None:
        print(f'[{Colors.BOLD}{Colors.GREEN}Part 2{Colors.END}] {response.content}')
    return {
        'messages': [response],
        'attempts': state.attempts - 1
    }

def found_xor_key(state: AgentState) -> dict:
    xor_key = state.messages[-1].tool_calls[0]['args']['xor_key']
    key_size = state.messages[-1].tool_calls[0]['args']['key_size']
    print(f'[{Colors.BOLD}{Colors.GREEN}FOUND_XOR_KEY{Colors.END}] {xor_key} ({key_size} bytes)')
    return {
        'messages': [
            ToolMessage(content='Ack', tool_call_id=state.messages[-1].tool_calls[0]['id']),
            HumanMessage(content='Found XOR key!')
        ],
        'xor_key': xor_key,
        'key_size': key_size
    }

def check1(state: AgentState) -> Literal["found_user_input", "tools", "bail"]:
    if state.attempts <= 0:
        return "bail"

    typ = state.messages[-1].tool_calls[0]['name']
    if typ == 'UserInput':
        return "found_user_input"
    else:
        return "tools"
    
def check2(state: AgentState) -> Literal["found_xor_key", "tools", "bail"]:
    if state.attempts <= 0:
        return "bail"

    typ = state.messages[-1].tool_calls[0]['name']
    if typ == 'XORKey':
        return "found_xor_key"
    else:
        return "tools"


def build_graph() -> StateGraph:
    graph = StateGraph(AgentState)

    graph.add_node("initialize", initialize)
    graph.add_node("act1", act1)
    graph.add_node("found_user_input", found_user_input)
    graph.add_node("act2", act2)
    graph.add_node("found_xor_key", found_xor_key)

    graph.add_node("tools1", ToolNode(tools=[run_python]))
    graph.add_node("tools2", ToolNode(tools=[run_python]))

    graph.set_entry_point("initialize")
    graph.add_edge("initialize", "act1")
    graph.add_conditional_edges(
        "act1", check1, {
            "found_user_input": "found_user_input",
            "tools": "tools1",
            "bail": END
        }
    )
    graph.add_edge("tools1", "act1")
    graph.add_edge("found_user_input", "act2")
    graph.add_conditional_edges(
        "act2", check2, {
            "found_xor_key": "found_xor_key",
            "tools": "tools2",
            "bail": END
        }
    )
    graph.add_edge("tools2", "act2")
    graph.add_edge("found_xor_key", END)

    return graph.compile()


def run_agent(code: str, mlil: str) -> dict:
    state = AgentState(
        code=code,
        mlil=mlil,
        user_input=None,
        xor_key=None,
        key_size=None
    )
    graph = build_graph()
    return graph.invoke(state)

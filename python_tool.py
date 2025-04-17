import os
import tempfile
import subprocess
import shutil
from langchain.tools import tool


# Python script template that will handle expressions like a Jupyter cell
SCRIPT_TEMPLATE = '''
import sys
import ast
from contextlib import redirect_stdout
import io

def run_cell(code_str):
    stdout_buffer = io.StringIO()
    try:
        # Parse code into AST
        parsed = ast.parse(code_str)
        
        # Redirect stdout to capture prints
        with redirect_stdout(stdout_buffer):
            # If the last node is an expression, handle separately
            if parsed.body and isinstance(parsed.body[-1], ast.Expr):
                # Separate last expression from other statements
                expr_node = parsed.body.pop()
                
                # Compile and execute initial statements (if any)
                if parsed.body:
                    exec(compile(ast.Module(body=parsed.body, type_ignores=[]), 
                                filename="<ast>", mode="exec"), globals())
                
                # Evaluate and print the result of the last expression
                result = eval(compile(ast.Expression(body=expr_node.value), 
                                    filename="<ast>", mode="eval"), globals())
                if result is not None:
                    print(result)
            else:
                # If no expression at the end, execute normally
                exec(code_str, globals())
                
        # Return captured stdout
        return stdout_buffer.getvalue()
    except Exception as e:
        return f"Error: {{str(e)}}"

# Execute the actual code passed to the script
user_code = """
{user_code}
"""

output = run_cell(user_code)
print(output)
'''

def _execute_code_in_subprocess(code, timeout=10):
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp()
    script_path = os.path.join(temp_dir, "execute_code.py")
    
    try:
        # Fill in the template with user code
        script_content = SCRIPT_TEMPLATE.format(
            user_code=code
        )
        
        # Write the script to the temporary file
        with open(script_path, 'w') as f:
            f.write(script_content)
        
        # Execute the script in a subprocess with timeout
        result = subprocess.run(
            ["python", script_path],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        # Return the output
        if result.returncode == 0:
            return result.stdout
        else:
            return f"Error (exit code {result.returncode}):\n{result.stderr}"
    
    except subprocess.TimeoutExpired:
        return f"Error: Execution timed out after {timeout} seconds."
    except Exception as e:
        return f"Error: {str(e)}"
    finally:
        # Clean up the temporary directory
        shutil.rmtree(temp_dir)

@tool
def run_python(code: str) -> str:
    """
    Run a python cell with a 10-second timeout in a separate process.
    """
    print('\n\n\033[33m[RUN_PYTHON]\033[0m\n', code)
    
    captured_output = _execute_code_in_subprocess(code)

    if len(captured_output) > 1000:
        captured_output = captured_output[:1000] + '...'
    
    print('\n\n\033[32m[RUN_PYTHON_OUTPUT]\033[0m\n', captured_output)
    return captured_output

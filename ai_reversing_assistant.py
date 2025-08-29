"""
IDA Pro AI Reversing Assistant

🔑 API Key Configuration Required!
You must configure your API key before use.

Setup Instructions:
1. Set directly in code. Replact <Enter your API Key Here> to your API key
2. API key can be obtained from https://hacky-ai.com
"""
import re
import asyncio
from typing import Optional, List
import tkinter as tk
from tkinter import ttk, messagebox

# IDA Pro modules (safe import)
try:
    import idaapi
    import idautils
    import idc
    import ida_typeinf
    import ida_funcs
    import ida_name
    import ida_hexrays
    import ida_kernwin
    IDA_AVAILABLE = True
except ImportError:
    IDA_AVAILABLE = False
    print("Warning: IDA Pro modules not available. Running in standalone mode.")

# HTTP client
import asyncio
import aiohttp

# Shared model definitions (included from shared/models.py)
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel

class ToolType(str, Enum):
    IDA_PRO = "ida_pro"
    GHIDRA = "ghidra"

class ParameterInfo(BaseModel):
    name: str
    type: str
    position: int

class FunctionSignature(BaseModel):
    name: str
    return_type: str
    parameters: List[ParameterInfo] = []

class VariableInfo(BaseModel):
    name: str
    current_type: str
    usage_pattern: List[str] = []
    function_context: Optional[str] = None

class FunctionInfo(BaseModel):
    current_signature: FunctionSignature
    address: int
    size: int
    call_references: List[int] = []

class AuthRequest(BaseModel):
    client_id: str
    api_key: str

class VariableAnalysisRequest(BaseModel):
    tool_type: ToolType
    variable_info: VariableInfo

class VariableAnalysisResponse(BaseModel):
    success: bool
    suggested_name: Optional[str] = None
    suggested_type: Optional[str] = None
    reasoning: Optional[str] = None
    error_message: Optional[str] = None

class FunctionAnalysisRequest(BaseModel):
    tool_type: ToolType
    function_info: FunctionInfo
    function_code: str

class FunctionAnalysisResponse(BaseModel):
    success: bool
    suggested_signature: Optional[FunctionSignature] = None
    suggested_comment: Optional[str] = None
    function_summary: Optional[str] = None
    reasoning: Optional[str] = None
    error_message: Optional[str] = None


class IDALLMClientConfig:
    """Client configuration"""
    def __init__(self):
        self.server_host = "ara.hacky-ai.com"
        self.server_port = 28001
        self.access_token = None
        self.session_id = None

        # API key configuration (user input required)
        self.api_key = "<Enter your API Key Here>"

        # Timeout settings (seconds)
        self.auth_timeout = 60      # Authentication request: 1 minute
        self.health_timeout = 30    # Server health check: 30 seconds
        self.variable_timeout = 120 # Variable analysis: 2 minutes
        self.function_timeout = 120 # Function analysis: 2 minutes

        # Comment language setting
        self.comment_language = "English"  # Default: English (korean/english)
    
    @property
    def base_url(self) -> str:
        return f"http://{self.server_host}:{self.server_port}"
    
    def load_config(self):
        """API key configuration check and user guidance"""
        if self.api_key == "<Enter your API Key Here>":
            print("=" * 60)
            print("⚠️  API key is not configured!")
            print("=" * 60)
            print("Usage instructions:")
            print("1. API key can be obtained from https://hacky-ai.com.")
            print("2. Search for <Enter your API Key Here> in the plugin source code and set your API key.")
            print("=" * 60)
            return False
        else:
            print(f"✅ API key configured: {self.api_key[:8]}...")
            return True
    



class IDAIntegration:
    """IDA Pro integration features"""

    @staticmethod
    def is_hexrays_available() -> bool:
        """Check if Hex-Rays decompiler is available"""
        if not IDA_AVAILABLE:
            return False
        try:
            return ida_hexrays.init_hexrays_plugin()
        except:
            return False
    
    @staticmethod
    def get_current_function_context() -> Optional[str]:
        """Return decompiled code of current function"""
        if not IDA_AVAILABLE:
            return "// Mock function context for testing"

        try:
            current_ea = idc.get_screen_ea()
            func_ea = idc.get_func_attr(current_ea, idc.FUNCATTR_START)

            if func_ea == idc.BADADDR:
                print("Current position is not inside a function.")
                return None

            # Use Hex-Rays decompiler (priority 1)
            if IDAIntegration.is_hexrays_available():
                try:
                    cfunc = ida_hexrays.decompile(func_ea)
                    if cfunc:
                        decompiled_code = str(cfunc)
                        if decompiled_code and len(decompiled_code.strip()) > 0:
                            return decompiled_code
                except Exception as e:
                    print(f"Hex-Rays decompiler failed: {e}")

            # Minimal function information (priority 3)
            func_name = idc.get_func_name(func_ea)
            func_size = idc.get_func_attr(func_ea, idc.FUNCATTR_END) - func_ea
            basic_info = f"// Function: {func_name}\n// Address: 0x{func_ea:x}\n// Size: {func_size} bytes"
            print(f"Generated context using basic function information: {func_name}")
            return basic_info

        except Exception as e:
            print(f"Function context extraction failed: {e}")
            return None
    
    @staticmethod
    def get_variable_at_cursor() -> Optional[VariableInfo]:
        """Extract variable information at cursor position (Hex-Rays only)"""
        if not IDA_AVAILABLE:
            return VariableInfo(name="mock_var", current_type="int", usage_pattern=[], function_context="mock function")

        try:
            current_ea = idc.get_screen_ea()

            # Debugging: Print current position information
            func_ea = idc.get_func_attr(current_ea, idc.FUNCATTR_START)
            if func_ea != idc.BADADDR:
                func_name = idc.get_func_name(func_ea)
            else:
                print("⚠️ Current position is not inside a function")

            cfunc = ida_hexrays.decompile(func_ea)
            if not cfunc:
                print("Hex-Rays decompilation failed")
                return None

            highlighted_var = IDAIntegration._get_selected_variable_name()
            function_context = IDAIntegration.get_current_function_context()
            actual_type = IDAIntegration._get_variable_actual_type(func_ea, highlighted_var)
            hexrays_var = VariableInfo(
                    name=highlighted_var,
                    current_type=actual_type,
                    usage_pattern=[],
                    function_context=function_context
                )

            if hexrays_var:
                # print(f"✓ Hex-Rays variable found: {hexrays_var.name} ({hexrays_var.current_type})")
                return hexrays_var

            print("❌ Hex-Rays variable not found.")
            print("   Click on the variable name you want to analyze with the mouse")
            print("--------------------------------")
            return None

        except Exception as e:
            print(f"Variable information extraction failed: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    @staticmethod
    def _get_variable_actual_type(func_ea: int, var_name: str) -> str:
        """Extract actual type information of variable"""
        try:
            widget = ida_kernwin.get_current_widget()
            if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_PSEUDOCODE:
                vdui = ida_hexrays.get_widget_vdui(widget)
                if vdui:
                    lvar = vdui.item.get_lvar()
                    if lvar:
                        # Get name and type directly from lvar object
                        variable_type = lvar.tif.dstr()
                        return variable_type
                    else:
                        print("❌ Variable type not found.")
                        return "int"
        except Exception as e:
            print(f"Error during type extraction: {e}")
            return "int"
    
    @staticmethod
    def get_current_function_info() -> Optional[FunctionInfo]:
        """Return current function information"""
        if not IDA_AVAILABLE:
            # Mock data for testing
            return FunctionInfo(
                current_signature=FunctionSignature(
                    name="test_function",
                    return_type="int",
                    parameters=[
                        ParameterInfo(name="param1", type="char*", position=0),
                        ParameterInfo(name="param2", type="int", position=1)
                    ]
                ),
                address=0x401000,
                size=100
            )

        try:
            current_ea = idc.get_screen_ea()
            func_ea = idc.get_func_attr(current_ea, idc.FUNCATTR_START)

            if func_ea == idc.BADADDR:
                return None

            # Collect function information
            func_name = idc.get_func_name(func_ea)
            func_size = idc.get_func_attr(func_ea, idc.FUNCATTR_END) - func_ea

            # Collect signature information
            signature = IDAIntegration._extract_function_signature(func_ea, func_name)

            return FunctionInfo(
                current_signature=signature,
                address=func_ea,
                size=func_size,
                call_references=list(idautils.CodeRefsTo(func_ea, 0))
            )

        except Exception as e:
            print(f"Function information extraction failed: {e}")
            return None
    
    @staticmethod
    def _extract_function_signature(func_ea: int, func_name: str) -> FunctionSignature:
        """Extract function signature"""
        try:
            # Use IDA Pro type information system (version compatibility considered)
            tinfo = ida_typeinf.tinfo_t()
            func_details = ida_typeinf.func_type_data_t()

            # Use different APIs depending on IDA Pro version
            tinfo_obtained = False
            try:
                # IDA Pro 7.x method
                if hasattr(ida_typeinf, 'get_tinfo'):
                    tinfo_obtained = ida_typeinf.get_tinfo(tinfo, func_ea)
                # IDA Pro 8.x+ method
                elif hasattr(ida_typeinf, 'get_tinfo2'):
                    tinfo_obtained = ida_typeinf.get_tinfo2(tinfo, func_ea)
                # IDA Pro 9.x+ method
                elif hasattr(ida_typeinf, 'get_tinfo3'):
                    tinfo_obtained = ida_typeinf.get_tinfo3(tinfo, func_ea)
            except Exception as e:
                print(f"Function type information extraction failed (API method): {e}")
                tinfo_obtained = False

            if tinfo_obtained and tinfo.get_func_details(func_details):
                # Return type
                return_type = str(func_details.rettype) if func_details.rettype else "int"

                # Parameters
                parameters = []
                try:
                    for i in range(func_details.size()):
                        param = func_details[i]
                        param_name = param.name if hasattr(param, 'name') and param.name else f"arg{i+1}"
                        param_type = str(param.type) if hasattr(param, 'type') and param.type else "int"
                        parameters.append(ParameterInfo(
                            name=param_name,
                            type=param_type,
                            position=i
                        ))
                except Exception as e:
                    print(f"Parameter extraction failed: {e}")

                return FunctionSignature(
                    name=func_name,
                    return_type=return_type,
                    parameters=parameters
                )

            # Default signature (fallback)
            print(f"Using default signature (function: {func_name})")
            return FunctionSignature(
                name=func_name,
                return_type="int",
                parameters=[]
            )

        except Exception as e:
            print(f"Signature extraction failed: {e}")
            return FunctionSignature(name=func_name, return_type="int", parameters=[])
        
    @staticmethod
    def _set_variable_type(cfunc, var_name: str, new_type_str: str) -> bool:
        """Set variable type (IDA Pro 9.1 compatible)"""
        try:
            """
            Change the type of a specific variable within the given cfunc.

            :param cfunc: cfunc_t object for the target function
            :param var_name: name of the variable to change type
            :param new_type_str: new C-style type string to apply
            :return: True on success, False on failure
            """
            # 1. Find lvar_t object by name in function's local variable list
            lvar_to_modify = None
            for lvar in cfunc.get_lvars():
                if lvar.name == var_name:
                    lvar_to_modify = lvar
                    break

            if not lvar_to_modify:
                print(f"⚠️ Type change failed: variable '{var_name}' not found in function.")
                return False

            new_type_info = ida_typeinf.tinfo_t()
            idati = ida_typeinf.get_idati()
            declaration_string = f"{new_type_str} {var_name};"

            if not ida_typeinf.parse_decl(new_type_info, idati, declaration_string, ida_typeinf.PT_SIL):
                print(f"⚠️ Type parsing failed: '{new_type_str}' is not recognized by IDA.")
                base_type_name = re.sub(r'[\s\*\[\]]+$', '', new_type_str)
                forward_decl = f"struct {base_type_name};"
                if ida_typeinf.parse_decls(idati, forward_decl, None, ida_typeinf.PT_SIL) != 0:
                    print(f"⚠️ Failed to add forward declaration '{forward_decl}'.")
                    return False
                print(f"✅ Forward declaration '{forward_decl}' added to Local Types.")
                if not ida_typeinf.parse_decl(new_type_info, idati, declaration_string, ida_typeinf.PT_SIL):
                    print(f"⚠️ Type parsing still failed after forward declaration: '{new_type_str}'")
                    return False

            if lvar_to_modify.set_lvar_type(new_type_info):
                print(f"✅ Variable type change successful: {var_name} -> {new_type_str}")
                return True
            else:
                print(f"⚠️ 'ida_hexrays.set_lvar_type' API call failed.")
                return False

        except Exception as e:
            print(f"Error during type setting: {e}")
            return False
    
    @staticmethod
    def apply_variable_changes(old_name: str, new_name: str, new_type: str) -> bool:
        if not IDA_AVAILABLE:
            return True

        try:
            current_ea = idc.get_screen_ea()

            # Check current function information
            func_ea = idc.get_func_attr(current_ea, idc.FUNCATTR_START)
            if func_ea == idc.BADADDR:
                print("⚠️ Cannot find function at current position.")
                return False

            # 1. Decompile function with Hex-Rays to get cfunc object
            cfunc = ida_hexrays.decompile(func_ea)
            if not cfunc:
                print("⚠️ Function decompilation failed.")
                return False

            # 2. Create list of all local variable names in current function (using set for fast lookup)
            #    Exclude old_name from duplicate check
            existing_names = {lvar.name for lvar in cfunc.get_lvars() if lvar.name != old_name}

            # 3. Name duplicate check and new name generation (core logic)
            final_name = new_name
            while final_name in existing_names:
                # Use regex to check if last part of name is a number
                match = re.match(r'^(.*?)(\d+)$', final_name)

                if match:
                    # If name ends with number: (base_name)(number+1)
                    base_name = match.group(1)
                    number = int(match.group(2))
                    final_name = f"{base_name}{number + 1}"
                else:
                    # If name doesn't end with number: (name)0
                    final_name = f"{final_name}0"

            # Use ida_hexrays.rename_lvar to modify variable name
            if hasattr(ida_hexrays, 'rename_lvar'):
                try:
                    success = ida_hexrays.rename_lvar(func_ea, old_name, final_name)
                    if success:
                        IDAIntegration._refresh_ida_views(func_ea)
                        # cfunc = ida_hexrays.decompile(func_ea)

                        # # Attempt type change
                        # if new_type:
                        #     IDAIntegration._set_variable_type(cfunc, final_name, new_type)

                        # # Refresh UI
                        # IDAIntegration._refresh_ida_views(func_ea)

                        return True
                    else:
                        print(f"⚠️ ida_hexrays.rename_lvar failed")
                except Exception as e:
                    print(f"ida_hexrays.rename_lvar error: {e}")

            return False

        except Exception as e:
            print(f"Variable change application failed: {e}")
            import traceback
            traceback.print_exc()
            return False

    @staticmethod
    def _refresh_ida_views(func_ea: int):
        try:
            current_widget = ida_kernwin.get_current_widget()
            widget_type = ida_kernwin.get_widget_type(current_widget)
            if widget_type != ida_kernwin.BWN_PSEUDOCODE:
                print("⚠️ Current widget is not Pseudocode")
                return

            vdui = ida_hexrays.get_widget_vdui(current_widget)
            if vdui:
                vdui.refresh_view(True)

        except Exception as e:
            print(f"Error during UI refresh: {e}")
    
    @staticmethod
    def _show_variable_rename_ui(old_name: str, new_name: str, new_type: str, reasoning: str) -> bool:
        # Apply changes immediately
        success = IDAIntegration.apply_variable_changes(old_name, new_name, new_type)
        if success:
            print(f"✅ Variable name change applied: {old_name} -> {new_name}")
            print(f"💬 Reason: {reasoning}")
            return True
        else:
            print("❌ Variable name change application failed")
            return False
    
    @staticmethod
    def apply_function_changes(signature: FunctionSignature, comment: str) -> bool:
        """Apply function changes"""
        if not IDA_AVAILABLE:
            print(f"[Mock] Function change: {signature.name} -> {signature.return_type}")
            print(f"[Mock] Comment: {comment}")
            return True

        try:
            current_ea = idc.get_screen_ea()
            func_ea = idc.get_func_attr(current_ea, idc.FUNCATTR_START)

            if func_ea == idc.BADADDR:
                return False

            # Change function name
            ida_name.set_name(func_ea, signature.name, ida_name.SN_CHECK)

            # Change function signature
            IDAIntegration._set_function_signature(func_ea, signature)

            # Add comment
            if comment:
                idc.set_func_cmt(func_ea, comment, 1)

            return True

        except Exception as e:
            print(f"Function change application failed: {e}")
            return False
    
    @staticmethod
    def _set_function_signature(func_ea: int, signature: FunctionSignature):
        """Set function signature"""
        try:
            # Compose function type
            func_details = ida_typeinf.func_type_data_t()

            # Set return type
            ret_tinfo = ida_typeinf.tinfo_t()
            if ida_typeinf.parse_decl(ret_tinfo, None, signature.return_type + ";", ida_typeinf.PT_TYP):
                func_details.rettype = ret_tinfo

            # Set parameters
            for param in signature.parameters:
                param_tinfo = ida_typeinf.tinfo_t()
                if ida_typeinf.parse_decl(param_tinfo, None, param.type + ";", ida_typeinf.PT_TYP):
                    funcarg = ida_typeinf.funcarg_t()
                    funcarg.type = param_tinfo
                    funcarg.name = param.name
                    func_details.push_back(funcarg)

            # Create and apply function type
            func_tinfo = ida_typeinf.tinfo_t()
            func_tinfo.create_func(func_details)
            ida_typeinf.apply_tinfo(func_ea, func_tinfo, ida_typeinf.TINFO_DEFINITE)

        except Exception as e:
            print(f"Signature setting failed: {e}")

    @staticmethod
    def _get_selected_variable_name() -> Optional[str]:
        """Get currently selected variable name in IDA Pro (highlight-based)"""
        try:
            # Method 1: Check function information at current cursor position
            cur_ea = ida_kernwin.get_screen_ea()
            pfn = ida_funcs.get_func(cur_ea)
            if not pfn:
                print("⚠️ Cursor is not positioned inside a function")
                return None

            # Method 2: Get highlighted text from current viewer
            v = ida_kernwin.get_current_viewer()
            if v:

                result = ida_kernwin.get_highlight(v)
                if result and len(result) >= 2:
                    highlighted_text = result[0]  # Highlighted text
                    flags = result[1]  # Highlight flags

                    if highlighted_text and highlighted_text.strip():
                        # Check if it's a valid variable name
                        if IDAIntegration._is_valid_variable_name(highlighted_text.strip()):
                            var_name = highlighted_text.strip()
                            return var_name
                        else:
                            print(f"⚠️ Highlighted text '{highlighted_text}' is not a valid variable name")
                    else:
                        print("⚠️ Highlighted text is empty")
                else:
                    print("⚠️ Cannot get highlight information")
            else:
                print("⚠️ Cannot get current viewer")

            print("⚠️ Cannot find selected variable name")
            return None

        except Exception as e:
            print(f"Failed to get selected variable name: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    @staticmethod
    def _is_valid_variable_name(text: str) -> bool:
        """Check if text is a valid variable name"""
        if not text or not text.strip():
            return False

        text = text.strip()

        if text.isdigit() or text.replace('_', '').replace('.', '').isdigit():
            return False

        if text[0].isdigit():
            return False

        special_chars = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
        if all(c in special_chars for c in text):
            return False

        # 4. Exclude too short strings (1 character or less)
        if len(text) < 1:
            return False

        # 5. Exclude too long strings (more than 50 characters)
        if len(text) > 50:
            return False

        # 6. Check general variable name pattern
        import re

        # Valid variable name pattern: consists of letters, numbers, underscores, starts with letter or underscore
        valid_pattern = r'^[a-zA-Z_][a-zA-Z0-9_]*$'

        if re.match(valid_pattern, text):
            return True
        else:
            print(f"Filtered: Invalid variable name pattern '{text}'")
            return False


class ServerClient:
    """Server communication client"""

    def __init__(self, config: IDALLMClientConfig):
        self.config = config

    async def authenticate(self) -> bool:
        """Server authentication"""
        try:
            auth_request = AuthRequest(
                client_id="ida_pro_client",
                api_key=self.config.api_key
            )

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.config.base_url}/auth",
                    json=auth_request.model_dump(),
                    timeout=aiohttp.ClientTimeout(total=self.config.auth_timeout)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        self.config.access_token = data.get("access_token")
                        if self.config.access_token:
                            return True
                        else:
                            print("Access token not found in response")
                            return False
                    else:
                        error_text = await response.text()
                        print(f"Authentication failed: {response.status} - {error_text}")
                        return False

        except asyncio.TimeoutError:
            print(f"Authentication request timeout ({self.config.auth_timeout} seconds exceeded)")
            return False
        except aiohttp.ClientError as e:
            print(f"HTTP client error: {e}")
            return False
        except Exception as e:
            print(f"Authentication failed: {e}")
            return False
    
    async def analyze_variable(self, request: VariableAnalysisRequest) -> Optional[VariableAnalysisResponse]:
        """Send variable analysis request"""
        try:
            if not self.config.access_token:
                print("Access token not available.")
                return None

            url = f"{self.config.base_url}/analyze/variable"
            headers = {
                "Authorization": f"Bearer {self.config.access_token}",
                "Content-Type": "application/json"
            }

            # Extract function_context separately from VariableInfo and include in request
            payload = {
                "tool_type": request.tool_type.value,
                "variable_info": {
                    "name": request.variable_info.name,
                    "current_type": request.variable_info.current_type,
                    "usage_pattern": request.variable_info.usage_pattern
                },
                "function_context": request.variable_info.function_context,
                "comment_language": self.config.comment_language  # 언어 설정 추가
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.config.variable_timeout)
                ) as response:

                    if response.status == 200:
                        data = await response.json()
                        return VariableAnalysisResponse(**data)
                    else:
                        error_text = await response.text()
                        print(f"Server error: {response.status} - {error_text}")
                        return None

        except asyncio.TimeoutError:
            print(f"Variable analysis request timeout ({self.config.variable_timeout} seconds exceeded)")
            return None
        except Exception as e:
            print(f"Variable analysis request failed: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    async def analyze_function(self, request: FunctionAnalysisRequest) -> Optional[FunctionAnalysisResponse]:
        """Function analysis request"""
        try:
            if not self.config.access_token:
                print("Authentication token not available. Please authenticate first.")
                return None

            headers = {"Authorization": f"Bearer {self.config.access_token}"}

            # 요청 데이터에 언어 설정 추가
            request_data = request.model_dump()
            request_data["comment_language"] = self.config.comment_language

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.config.base_url}/analyze/function",
                    json=request_data,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.config.function_timeout)
                ) as response:
                    print(f"Server response status: {response.status}")

                    if response.status == 200:
                        data = await response.json()
                        return FunctionAnalysisResponse(**data)
                    else:
                        error_text = await response.text()
                        print(f"Server error response: {response.status} - {error_text}")
                        return None

        except asyncio.TimeoutError:
            print(f"Function analysis request timeout ({self.config.function_timeout} seconds exceeded)")
            return None
        except aiohttp.ClientError as e:
            print(f"HTTP client error: {e}")
            return None
        except Exception as e:
            print(f"Function analysis request failed: {e}")
            return None


class SettingsDialog:
    """Settings dialog"""

    def __init__(self, config: IDALLMClientConfig):
        self.config = config
        self.result = None

    def show(self) -> bool:
        """Display settings dialog"""
        root = tk.Tk()
        root.title("AI Reversing Assistant Settings")
        root.geometry("500x220")  # Restore original size
        root.resizable(False, False)

        # Title
        title_label = ttk.Label(root, text="AI Reversing Assistant Settings", font=("Arial", 12, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(20, 10))

        # Comment language setting (user selectable)
        ttk.Label(root, text="Comment Language:").grid(row=1, column=0, sticky="w", padx=10, pady=5)
        # Convert internal values 'korean'/'english' to UI values 'Korean'/'English'
        internal_language = getattr(self.config, 'comment_language', 'English')
        if internal_language == 'Korean':
            display_language = 'Korean'
        elif internal_language == 'English':
            display_language = 'English'
        else:
            display_language = 'English'  # Default

        comment_language_var = tk.StringVar(value=display_language)
        comment_language_combo = ttk.Combobox(root, textvariable=comment_language_var, width=27, state="readonly")
        comment_language_combo['values'] = ['Korean', 'English']
        comment_language_combo.grid(row=1, column=1, padx=10, pady=5)

        # Settings information text
        info_frame = ttk.Frame(root)
        info_frame.grid(row=2, column=0, columnspan=2, pady=5)
        info_label = ttk.Label(info_frame, text="※ Settings are stored in memory only (No file saving)", foreground="blue", font=("Arial", 9))
        info_label.pack()

        # Button frame
        button_frame = ttk.Frame(root)
        button_frame.grid(row=3, column=0, columnspan=2, pady=20)

        def save_settings():
            try:
                # Save comment language setting
                selected_language = comment_language_var.get()
                # Convert UI values 'Korean'/'English' to internal values 'korean'/'english'
                if selected_language == 'Korean':
                    self.config.comment_language = 'Korean'
                elif selected_language == 'English':
                    self.config.comment_language = 'English'
                else:
                    self.config.comment_language = 'English'  # Default

                self.result = True
                root.destroy()
                messagebox.showinfo("Success", "Settings saved to memory.\n(No file saving)")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save settings: {e}")

        def cancel():
            self.result = False
            root.destroy()

        ttk.Button(button_frame, text="Save", command=save_settings).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=cancel).pack(side=tk.LEFT, padx=5)

        root.mainloop()
        return self.result or False


class IDALLMClient:
    """IDA Pro LLM client main class"""

    def __init__(self):
        self.config = IDALLMClientConfig()
        self.config.load_config()
        self.server_client = ServerClient(self.config)
        self.authenticated = False

    async def initialize(self) -> bool:
        """Client initialization"""
        try:
            # API key configuration check
            if not self.config.load_config():
                print("❌ API key is not configured.")
                return False

            # Server authentication
            if await self.server_client.authenticate():
                self.authenticated = True
                print("Server authentication successful")
                return True
            else:
                print("Server authentication failed")
                return False
        except Exception as e:
            print(f"Initialization failed: {e}")
            return False

    def show_settings(self):
        """Display settings dialog"""
        dialog = SettingsDialog(self.config)
        if dialog.show():
            self.server_client = ServerClient(self.config)
            self.authenticated = False
    
    async def analyze_variable_at_cursor(self) -> bool:
        """Analyze variable at cursor position and modify variable name and type"""
        print("--------------------------------")
        try:
            if not self.authenticated:
                if not await self.initialize():
                    print("Authentication failed.")
                    return False

            variable_info = IDAIntegration.get_variable_at_cursor()

            if not variable_info:
                print("Cannot extract variable information.")
                return False

            if not variable_info.function_context:
                print("Function context not available.")
                return False

            request = VariableAnalysisRequest(
                tool_type=ToolType.IDA_PRO,
                variable_info=variable_info
            )

            response = await self.server_client.analyze_variable(request)

            if response and response.success:
                # Display user selection UI
                if IDA_AVAILABLE and hasattr(ida_kernwin, 'Choose'):
                    success = IDAIntegration._show_variable_rename_ui(
                        variable_info.name,
                        response.suggested_name or variable_info.name,
                        response.suggested_type or variable_info.current_type,
                        response.reasoning or ""
                    )
                else:
                    # Auto-apply in standalone mode
                    success = IDAIntegration.apply_variable_changes(
                        variable_info.name,
                        response.suggested_name or variable_info.name,
                        response.suggested_type or variable_info.current_type
                    )

                if success:
                    # if response.suggested_type != variable_info.current_type:
                    #     print(f"Type change: {variable_info.current_type} -> {response.suggested_type}")
                    return True
                else:
                    print("Failed to apply changes.")
                    return False
            else:
                error_msg = response.error_message if response else "No server response"
                print(f"Variable analysis failed: {error_msg}")
                if response:
                    print(f"Response details: {response}")
                return False

        except Exception as e:
            print(f"Variable analysis failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    async def analyze_function_at_cursor(self) -> bool:
        """Analyze function at cursor position"""
        try:
            if not self.authenticated:
                if not await self.initialize():
                    print("Authentication failed.")
                    return False

            function_info = IDAIntegration.get_current_function_info()
            function_context = IDAIntegration.get_current_function_context()

            if not function_info or not function_context:
                print("Cannot extract function information.")
                return False

            request = FunctionAnalysisRequest(
                tool_type=ToolType.IDA_PRO,
                function_info=function_info,
                function_code=function_context
            )

            response = await self.server_client.analyze_function(request)

            if response and response.success:
                # Apply changes
                success = IDAIntegration.apply_function_changes(
                    response.suggested_signature or function_info.current_signature,
                    response.suggested_comment or ""
                )

                if success:
                    # Try to refresh UI
                    try:
                        current_ea = idc.get_screen_ea()
                        func_ea = idc.get_func_attr(current_ea, idc.FUNCATTR_START)
                        IDAIntegration._refresh_ida_views(func_ea)
                    except Exception as e:
                        print(f"Error during UI refresh: {e}")

                    return True
                else:
                    print("Failed to apply changes.")
                    return False
            else:
                error_msg = response.error_message if response else "No server response"
                print(f"Function analysis failed: {error_msg}")
                if response:
                    print(f"Response details: {response}")
                return False

        except Exception as e:
            print(f"Function analysis failed: {e}")
            import traceback
            traceback.print_exc()
            return False


# ============ IDA Pro Plugin Interface ============

if IDA_AVAILABLE:
    # Global client instance
    llm_client = IDALLMClient()

    class AIReversingAssistantPlugin(idaapi.plugin_t):
        """IDA Pro AI Reversing Assistant Plugin"""

        flags = idaapi.PLUGIN_KEEP
        comment = "AI-powered variable/function analysis automation"
        help = "Shift+N: AI analysis with automatic variable/function detection"
        wanted_name = "AI Reversing Assistant"
        wanted_hotkey = ""

        def init(self):
            print("AI Reversing Assistant plugin loaded")
            return idaapi.PLUGIN_KEEP

        def run(self, arg):
            llm_client.show_settings()

        def term(self):
            print("AI Reversing Assistant plugin terminated")

    # Integrated action handler
    class UnifiedAnalysisAction(idaapi.action_handler_t):
        def activate(self, ctx):
            # Determine if highlighted value is variable or function
            current_ea = idc.get_screen_ea()

            # Check if current position is inside a function
            func_ea = idc.get_func_attr(current_ea, idc.FUNCATTR_START)

            if func_ea != idc.BADADDR:
                # Inside function - try variable analysis

                func_name = idc.get_func_name(func_ea)
                highlighted_var = IDAIntegration._get_selected_variable_name()
                if func_name == highlighted_var:
                    print(f"Function detected: {highlighted_var}, running function analysis...")
                    asyncio.run(llm_client.analyze_function_at_cursor())
                    return 1
                else:
                    print(f"Variable detected: {highlighted_var}, running variable analysis...")
                    asyncio.run(llm_client.analyze_variable_at_cursor())
                    return 1
            return 0

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS


    # Action registration
    def register_actions():
        # Unified analysis action
        unified_action = idaapi.action_desc_t(
            "ai_reversing_assistant:unified_analysis",
            "AI Analysis (Auto-detect Variable/Function)",
            UnifiedAnalysisAction(),
            "Shift+E",
            "AI-powered analysis with automatic variable/function detection"
        )

        idaapi.register_action(unified_action)

    # Plugin entry point
    def PLUGIN_ENTRY():
        register_actions()
        return AIReversingAssistantPlugin()

else:
    # Do nothing in environments where IDA Pro is not available
    pass

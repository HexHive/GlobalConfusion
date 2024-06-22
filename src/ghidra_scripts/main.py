import os

from decompile_util import SignatureChanger, Decompiler, TOCTOUAnalyzer
import helpers

################################################################################
# TYPING
################################################################################

from typing import List
from ghidra.program.database import ProgramDB
from ghidra.program.database.function import FunctionDB
from ghidra.app.decompiler import DecompileResults

################################################################################
# LOGGING
################################################################################

import logging

FORMAT = "%(asctime)s,%(msecs)d %(levelname)-8s " "%(message)s"
logging.basicConfig(
    format=FORMAT, datefmt="%Y-%m-%d:%H:%M:%S", level=logging.DEBUG
)
log = logging.getLogger(__name__)

################################################################################
# GLOBALS
################################################################################

DATA_BASE_DIR = "/data"
INVOKE_COMMAND_FUNC_NAME = "TA_InvokeCommandEntryPoint"
OPEN_SESSION_FUNC_NAME = "TA_OpenSessionEntryPoint"

################################################################################
# CODE
################################################################################


def main():
    """
    The main function that orchestrates data type creation, function
    signature change, decompilation, and symbol processing.
    """
    logging.info("Initializing...")
    program: ProgramDB = getCurrentProgram()

    # Obtain the `TA_InvokeCommandEntryPoint` function
    invoke_command_funcs: List[FunctionDB] = getGlobalFunctions(
        INVOKE_COMMAND_FUNC_NAME
    )

    # Assert that we have found the function
    n_funcs = len(invoke_command_funcs)
    assert n_funcs == 1, f"Number of funcs is {n_funcs}, expected 1"
    invoke_command_func: FunctionDB = invoke_command_funcs[0]

    # Apply the well-known function signatures to `TA_InvokeCommandEntryPoint`
    # and `TA_OpenSessionEntryPoint`
    logging.info("Changing function signatures...")
    data_type_manager = SignatureChanger(program)
    data_type_manager.apply_signature(INVOKE_COMMAND_FUNC_NAME)
    data_type_manager.apply_open_session_entrypoint_signature(
        OPEN_SESSION_FUNC_NAME
    )

    # Decompile the `TA_InvokeCommandEntryPoint` function
    # TODO: Extend this to `TA_OpenSessionEntryPoint`
    logging.info("Decompiling...")
    decompiler = Decompiler(program)
    decompiled_func: DecompileResults = decompiler.decompile_function(
        invoke_command_func
    )

    logging.info("Processing symbols...")
    analyzer = TOCTOUAnalyzer(program)
    analyzer.process_symbols(decompiled_func)

    filename = f"{program.getName()}_full.pdf"
    path = os.path.join(DATA_BASE_DIR, filename)
    analyzer.reachability_graph.render(path)


if __name__ == "__main__":
    main()

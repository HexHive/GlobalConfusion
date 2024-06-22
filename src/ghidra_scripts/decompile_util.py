from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import *
from ghidra.program.model.listing import *
from ghidra.program.model.pcode import *
from ghidra.program.model.address import *
from ghidra.program.model.data import (
    UnionDataType,
    StructureDataType,
    PointerDataType,
    IntegerDataType,
    LongDataType,
    VoidDataType,
    UnsignedIntegerDataType,
    UnsignedLongDataType,
)
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import (
    ParameterDefinitionImpl,
    FunctionDefinitionDataType,
)
from ghidra.program.model.symbol import SourceType
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.program.model.pcode import (
    VarnodeAST,
    HighSymbol,
    PcodeOp,
    PcodeOpAST,
    HighOther,
    HighFunction,
    HighVariable,
    LocalSymbolMap,
    PcodeBlockBasic,
)
from ghidra.app.decompiler import DecompileResults
from ghidra.program.database.function import FunctionDB
from ghidra.program.database import ProgramDB

from graphhelper import GraphHelper
from enum import Enum
from helpers import pp


################################################################################
# TYPING
################################################################################

from typing import List, Dict

################################################################################
# LOGGING
################################################################################

import logging

log = logging.getLogger(__name__)
log.setLevel(logging.WARN)

################################################################################
# GLOBALS
################################################################################

INVOKE_COMMAND_FUNC_NAME = "TA_InvokeCommandEntryPoint"
OPEN_SESSION_FUNC_NAME = "TA_OpenSessionEntryPoint"

################################################################################
# UTILS
################################################################################


def is_64bit_program(program: ProgramDB) -> bool:
    """
    Check if the program is 64 bit.

    Args:
        program (ProgramDB): the program to check

    Returns:
        bool: returns True if the program is 64 bit, False otherwise
    """
    with open(program.getExecutablePath(), "rb") as f:
        return f.read(5)[-1] == 2


################################################################################
# CODE
################################################################################


class InstructionType(Enum):
    """
    Specifies the type of an instruction
    """

    FETCH = 1
    USE = 2
    NONE = 3


class Instruction:
    """
    Represents an instruction
    """

    def __init__(
        self, entity, instruction_type: InstructionType = InstructionType.NONE
    ):
        """
        Initialize the Instruction attributes

        Args:
            entity (PcodeOpAST | VarnodeAST): the entity of the instruction
            instruction_type (InstructionType): the type of the instruction
        """
        self.entity = entity
        self.instruction_type = instruction_type

    def get_address(self) -> int:
        """
        Get the address of the instruction.

        Returns:
            int: the address of the instruction
        """
        return (
            self.entity.getPCAddress().getOffset()
            if isinstance(self.entity, VarnodeAST)
            else self.entity.getSeqnum().getTarget().getOffset()
        )

    def get_id(self) -> int:
        """
        Get the id of the instruction.

        Returns:
            int: the id of the instruction
        """
        return (
            self.entity.getUniqueId()
            if isinstance(self.entity, VarnodeAST)
            else self.entity.hashCode()
        )

    def __str__(self):
        addr = hex(self.get_address())
        return (
            f"{self.entity}\n Address: {addr}\n Type: {self.instruction_type}"
            if self.instruction_type != InstructionType.NONE
            else f"{self.entity}\nAddress: {addr}\n"
        )


class SignatureChanger:
    """
    A class for managing the creation of new function signatures.
    """

    def __init__(self, program: ProgramDB):
        """
        Initialize the SignatureChanger attributes

        Args:
            program (ProgramDB): the program to change the signatures of
        """
        self.data_type_manager = program.getDataTypeManager()
        self.root_category = self.data_type_manager.getRootCategory()
        self.category_path = self.root_category.getCategoryPath()
        self.is_64bit = is_64bit_program(program)
        log.debug(f"64-bit: {self.is_64bit}")

    def apply_signature(self, func_name: str) -> bool:
        """
        Apply the function signatures if known.

        Args:
            func_name (str): the name of the function
        """
        if self.is_64bit:
            self.create_TC_NS_Parameter_64bit()
        else:
            self.create_TC_NS_Parameter()

        if func_name == INVOKE_COMMAND_FUNC_NAME:
            self.change_invoke_command_signature(func_name)
        elif func_name == OPEN_SESSION_FUNC_NAME:
            self.change_open_session_signature(func_name)
        else:
            return False
        return True

    def create_TC_NS_Parameter(self) -> None:
        """
        Create custom data types for TC_NS_Parameter.
        """
        memref_struct = StructureDataType(self.category_path, "memref", 0)
        memref_struct.insertAtOffset(
            0x0,
            PointerDataType(VoidDataType()),
            0x4,
            "buffer",
            None,
        )
        memref_struct.insertAtOffset(
            0x4, UnsignedIntegerDataType(), 0, "size", None
        )

        value_struct = StructureDataType(self.category_path, "value", 0)
        value_struct.insertAtOffset(0x0, IntegerDataType(), 0, "a", None)
        value_struct.insertAtOffset(0x4, IntegerDataType(), 0, "b", None)

        union = UnionDataType(self.category_path, "TC_NS_Parameter")

        union.add(memref_struct, 0, "memref", None)
        union.add(value_struct, 0, "value", None)

        self.data_type_manager.addDataType(memref_struct, None)
        self.data_type_manager.addDataType(value_struct, None)
        self.data_type_manager.addDataType(union, None)

    def create_TC_NS_Parameter_64bit(self) -> None:
        """
        Create custom data types for TC_NS_Parameter for 64 bit.
        """
        memref_struct = StructureDataType(self.category_path, "memref", 0x8)
        memref_struct.insertAtOffset(
            0x0,
            PointerDataType(VoidDataType()),
            0x8,
            "buffer",
            None,
        )
        memref_struct.insertAtOffset(
            0x8, UnsignedLongDataType(), 0x8, "size", None
        )

        value_struct = StructureDataType(self.category_path, "value", 0x8)
        value_struct.insertAtOffset(0x0, LongDataType(), 0x8, "a", None)
        value_struct.insertAtOffset(0x8, LongDataType(), 0x8, "b", None)

        union = UnionDataType(self.category_path, "TC_NS_Parameter")

        union.add(memref_struct, 0, "memref", None)
        union.add(value_struct, 0, "value", None)

        self.data_type_manager.addDataType(memref_struct, None)
        self.data_type_manager.addDataType(value_struct, None)
        self.data_type_manager.addDataType(union, None)

    def change_invoke_command_signature(self, function_name: str) -> None:
        """
        Change the signature of the specified function based on the invoke command function.

        Args:
            function_name (str): The name of the function to change the signature of
        """
        function = getGlobalFunctions(function_name)
        if not function:  # if function is empty
            return
        else:
            function = function[0]

        return_type = UnsignedIntegerDataType()
        params = [
            ParameterDefinitionImpl(
                "session_obj", PointerDataType(VoidDataType()), None
            ),
            ParameterDefinitionImpl("cmd_id", UnsignedIntegerDataType(), None),
            ParameterDefinitionImpl(
                "param_types", UnsignedIntegerDataType(), None
            ),
            ParameterDefinitionImpl(
                "params",
                PointerDataType(
                    self.data_type_manager.getDataType("/TC_NS_Parameter")
                ),
                None,
            ),
        ]

        new_signature = FunctionDefinitionDataType(
            self.category_path, function_name
        )
        new_signature.setReturnType(return_type)
        new_signature.setArguments(params)

        cmd = ApplyFunctionSignatureCmd(
            function.getEntryPoint(),
            new_signature,
            SourceType.USER_DEFINED,
        )
        runCommand(cmd)

    def change_open_session_signature(self, function_name: str) -> None:
        """
        Change the signature of the specified function based on the open session function.

        Args:
            function_name (str): The name of the function to change the signature of
        """
        function = getGlobalFunctions(function_name)
        if not function:  # if function is empty
            return
        else:
            function = function[0]

        return_type = UnsignedIntegerDataType()
        params = [
            ParameterDefinitionImpl(
                "session_obj",
                PointerDataType(PointerDataType(VoidDataType())),
                None,
            ),
            ParameterDefinitionImpl(
                "param_types", UnsignedIntegerDataType(), None
            ),
            ParameterDefinitionImpl(
                "params",
                PointerDataType(
                    self.data_type_manager.getDataType("/TC_NS_Parameter")
                ),
                None,
            ),
        ]

        new_signature = FunctionDefinitionDataType(
            self.category_path, function_name
        )
        new_signature.setReturnType(return_type)
        new_signature.setArguments(params)

        cmd = ApplyFunctionSignatureCmd(
            function.getEntryPoint(),
            new_signature,
            SourceType.USER_DEFINED,
        )
        runCommand(cmd)


class DecompilerException(Exception):
    pass


class Decompiler:
    """
    A class for decompiling functions.
    """

    def __init__(self, program: Program):
        """
        Initialize the Decompiler attributes
        """
        self.monitor = ConsoleTaskMonitor()
        self.decomp_interface = DecompInterface()
        self.decomp_interface.setOptions(DecompileOptions())
        self.decomp_interface.openProgram(program)

        self._cache: Dict[Function, DecompileResults] = dict()

    def decompile_function(self, function: Function) -> DecompileResults:
        """
        Decompile the specified function.

        Args:
            function (FunctionDB): the function to decompile

        Returns:
            DecompileResults: decompiled function
        """
        return self.decomp_interface.decompileFunction(
            function, 60, self.monitor
        )

    def get_argument_varnode(
        self, func: Function, param_idx: int, empty_ok: bool = False
    ) -> VarnodeAST:

        if func in self._cache:
            log.debug(
                f"func {func.getName()}@{func.getEntryPoint()} already in decompilation cache!"
            )
            decompiled_func = self._cache[func]
        else:
            log.debug(
                f"decompiling func {func.getName()}@{func.getEntryPoint()}..."
            )
            decompiled_func = self.decompile_function(func)
            self._cache[func] = decompiled_func

        high_func: HighFunction = decompiled_func.getHighFunction()
        lsm: LocalSymbolMap = high_func.getLocalSymbolMap()
        try:
            params_symb: HighSymbol = lsm.getParamSymbol(param_idx)
        except IndexError as e:
            log.warning(e)
            raise DecompilerException()
        high_var: HighVariable = params_symb.getHighVariable()

        if high_var is None and empty_ok:
            return None
        assert (
            high_var is not None
        ), f"Could not find HighVariable for parameter at idx {param_idx}"

        instance: VarnodeAST = high_var.getRepresentative()
        return instance


class TOCTOUAnalyzer:
    """
    A class for processing symbols and their instances.
    """

    class BasicBlock:
        """
        A class for representing a basic block, with start, stop addresses
        and a list of instructions.
        """

        def __init__(self, bb: PcodeBlockBasic):
            """
            Initialize the basic block attributes

            Args:
                bb (PcodeBlockBasic): the basic block to extract start
                and stop addresses from
            """
            self.start: int = bb.getStart().getOffset()
            self.stop: int = bb.getStop().getOffset()
            self.instructions: List[Instruction] = []

        def add_instruction(self, instruction: Instruction) -> None:
            """
            Add the instruction to the list of instructions.

            Args:
                instruction (Instruction): the instruction to add
            """
            self.instructions.append(instruction)

        def get_nearest_parent_id(self, address: int, desc_id: int) -> int:
            """
            Get the id of the parent with the nearest address in the basic block,
            in order to add an edge to the descendant.

            Args:
                address (int): the address of the descendant
                desc_id (int): the id of the descendant

            Returns:
                int: the id of the nearest parent in the basic block or -1 if empty
            """
            nearest_addr = -1
            nearest_id = -1
            # Start searching from the last instruction added
            for ins in reversed(self.instructions):
                ins_address = ins.get_address()
                if (
                    ins_address > nearest_addr
                    and ins_address <= address
                    and ins.get_id()
                    != desc_id  # Make sure that the parent is not the descendant itself
                ):
                    nearest_addr = ins_address
                    nearest_id = ins.get_id()
            return nearest_id

        def __str__(self):
            return f"start: {hex(self.start)}, stop: {hex(self.stop)}"

        def __repr__(self):
            return self.__str__()

    def __init__(self, program: ProgramDB):
        """
        Initialize the analyzer's attributes

        Args:
            program (ProgramDB): the program to process the symbols of
        """
        self.num_params = 4
        # the descendants of the params based on the params index
        self.descendants = [[] for _ in range(self.num_params)]
        # for each params index, keeps track of the visited descendants based on the unique id
        self.visited_descendants = [{} for _ in range(self.num_params)]
        self.reachability_graph = GraphHelper()
        self.fetch_function_names = ["strlen"]
        self.use_function_names = [
            "strcat",
            "strncat",
            "printf",
            "strcpy",
            "strncpy",
            "memcpy",
            "memset",
            "malloc",
            "free",
        ]
        self.function_manager = program.getFunctionManager()
        self.multiplier_64bit = 2 if is_64bit_program(program) else 1
        self.basic_blocks = []

    def process_symbols(self, decompiled_func: DecompileResults) -> None:
        """
        Starting from params symbol initiate the processing of the instances.

        Args:
            decompiled_func (DecompileResults): the decompiled function to get the symbols from
        """
        # Reset fetches
        self.descendants = [[] for _ in range(self.num_params)]
        self.visited_descendants = [{} for _ in range(self.num_params)]

        high_func: HighFunction = decompiled_func.getHighFunction()

        # Get the basic blocks for each params
        basic_blocks = [
            self.BasicBlock(bb) for bb in high_func.getBasicBlocks()
        ]
        # Order basic_blocks by start address
        basic_blocks.sort(key=lambda x: x.start)
        for _ in range(self.num_params):
            self.basic_blocks.append(basic_blocks)

        lsm: LocalSymbolMap = high_func.getLocalSymbolMap()

        # The 3rd parameter of `TA_InvokeCommandEntryPoint` is the params array.
        params_symb: HighSymbol = lsm.getParamSymbol(3)
        high_var: HighVariable = params_symb.getHighVariable()
        assert high_var is not None, "Could not find `params` parameter"

        # `high_var` should represent the `params` parameter, thus we expect
        # there to be only one instance
        instances: List[VarnodeAST] = high_var.getInstances()
        assert (
            len(instances) == 1
        ), f"Number of `params` instances is {len(instances)}, expected 1."

        # TODO: if it's true that we only expect one instance, the param to
        # `_locate_params` can be changed to a single `VarnodeAST.`
        first_level_descendants = self._locate_params(instances)

        self.process_params_instances(first_level_descendants)

    def process_params_instances(self, instances: List[VarnodeAST]) -> None:
        """
        Process the isolated params instances, get the corresponding
        params index and basic block index, and process the descendants.

        Args:
            instances (List[VarnodeAST]): list of params instances
        """

        for params_instance in instances:
            log.debug(pp(params_instance))

            params_index: int = self.get_params_index(params_instance)
            if params_index == -1:
                log.debug(f"{params_instance} is not a memref.buffer instance")
                continue
            log.debug(f"{params_instance} is at index {params_index}")

            # Create the instruction and add it to the descendants list
            instance_id: int = params_instance.getUniqueId()
            instruction: Instruction = Instruction(params_instance)
            self.visited_descendants[params_index][instance_id] = True
            self.descendants[params_index].append(instruction)

            # Get the basic block index of the params instance
            instance_bb_index = self.get_bb_index(
                params_index, params_instance.getPCAddress().getOffset()
            )
            if instance_bb_index == -1:
                log.debug(f"{params_instance} is not in a basic block")
                continue

            # Create the set of the next basic block indexes
            # to find the nearest parent for each descendant
            next_bb_indexes = set()
            next_bb_indexes.add(instance_bb_index)

            # Add the instance instruction to the basic block
            self.basic_blocks[params_index][instance_bb_index].add_instruction(
                instruction
            )

            # Add the instance node to the graph
            self.reachability_graph.add_node(
                instance_id,
                label=f"{str(instruction)}\nbbindex: {str(instance_bb_index)}",
            )

            self.process_params_descendants(
                params_instance, params_index, next_bb_indexes
            )

    def process_params_descendants(
        self,
        instance: VarnodeAST,
        params_index: int,
        next_bb_indexes: set,
    ) -> None:
        """
        Process the descendants of the specified instance.

        Args:
            instance (VarnodeAST): the instance to process
            params_index (int): the index of the params
            next_bb_indexes (set): the set of the next basic block indexes
        """
        descendants: List[PcodeOpAST] = instance.getDescendants()
        for desc in descendants:
            self.process_descendant(desc, params_index, next_bb_indexes)

    def process_descendant(
        self, desc: PcodeOpAST, params_index: int, next_bb_indexes: set
    ) -> set:
        """
        Process the specified descendant:
        add the descendant to the descendants list,
        add the descendant node to the graph,
        add an edge from the nearest parent in the
        basic block to the descendant,
        add the descendant instruction to the basic block,
        recursively process the descendant's descendants.

        Args:
            desc (PcodeOpAST): the descendant to process
            params_index (int): the index of the params
            next_bb_indexes (set): the set of the next basic block indexes

        Returns:
            set: the set of the next basic block indexes
                 with the descendant's basic block index added
        """
        desc_id: int = desc.hashCode()
        if desc_id not in self.visited_descendants[params_index]:
            log.debug(pp(desc))

            # Create the instruction and add it to the descendants list
            instruction: Instruction = Instruction(desc)
            self.descendants[params_index].append(instruction)

            # Mark the descendant as visited
            self.visited_descendants[params_index][desc_id] = True

            # Get the descendant's basic block index
            desc_addr = desc.getSeqnum().getTarget().getOffset()
            desc_bb_index = self.get_bb_index(params_index, desc_addr)
            if desc_bb_index == -1:
                log.debug(f"{desc} {hex(desc_addr)} is not in a basic block")
                return

            # Add the descendant node to the graph
            self.reachability_graph.add_node(
                desc_id,
                label=f"{str(instruction)}\nbb_index: {str(desc_bb_index)}",
            )

            # Find the bb index of the parent with the nearest bb index
            nearest_parent_bb_index = -1
            for bb_index in next_bb_indexes:
                if (
                    bb_index > nearest_parent_bb_index
                    and bb_index <= desc_bb_index
                ):
                    nearest_parent_bb_index = bb_index

            # Find the id of the parent in the nearest basic block with the nearest address
            # and add the descendant basic block index to the set of the next basic block indexes
            nearest_parent_id = self.basic_blocks[params_index][
                nearest_parent_bb_index
            ].get_nearest_parent_id(desc_addr, desc_id)
            next_bb_indexes.add(desc_bb_index)

            if nearest_parent_id == -1:
                log.debug(f"No nearest parent for {desc} 0x{hex(desc_addr)}")
                return

            # Add the edge from the nearest parent to the descendant
            # and add the descendant instruction to the basic block
            self.reachability_graph.add_edge(nearest_parent_id, desc_id)
            self.basic_blocks[params_index][desc_bb_index].add_instruction(
                instruction
            )

            output: VarnodeAST = desc.getOutput()
            if output:
                # Call the function recursively on the descendant's descendants
                output_descendants: List[PcodeOpAST] = output.getDescendants()
                for output_desc in output_descendants:
                    next_bb_indexes = self.process_descendant(
                        output_desc, params_index, next_bb_indexes
                    )

        return next_bb_indexes

    def _locate_params(self, instances: List[VarnodeAST]) -> List[VarnodeAST]:
        """
        Locate the first-level descendants corresponding to potential memref
        parameters.

        Args:
            instances (List[VarnodeAST]): the instances to isolate

        Returns:
            List[VarnodeAST]: list of the first-level descendants accessing memref parameters
        """

        first_descendants: List[VarnodeAST] = []
        for instance in instances:
            log.debug(pp(instance))
            # Retrieve the first-level descendants for `params`
            descendants: List[PcodeOpAST] = instance.getDescendants()
            for desc in descendants:
                output: VarnodeAST = desc.getOutput()
                log.debug(pp(output))
                if output:
                    high_out: HighOther = output.getHigh()
                    if high_out:
                        high_out_instances: List[VarnodeAST] = (
                            high_out.getInstances()
                        )
                        first_descendants.extend(high_out_instances)
        return first_descendants

    def get_params_index(self, instance: VarnodeAST) -> int:
        """
        Get the index of the params->memref.buffer instance.

        Args:
            instance (VarnodeAST): the params instance

        Returns:
            int: index or -1 if it is not a memref.buffer instance
        """
        for raw_pcode in self.get_raw_pcode(instance):
            if raw_pcode.getOpcode() == PcodeOp.INT_ADD:
                offset_input: VarnodeAST = raw_pcode.getInput(1)
                if offset_input.isConstant():
                    offset: int = offset_input.getOffset()
                    if offset == 0x0 * self.multiplier_64bit:
                        return 0
                    elif offset == 0x8 * self.multiplier_64bit:
                        return 1
                    elif offset == 0x10 * self.multiplier_64bit:
                        return 2
                    elif offset == 0x18 * self.multiplier_64bit:
                        return 3
        return -1

    def get_bb_index(self, params_index, address: int) -> int:
        """
        Get the index of the basic block containing the specified address.

        Args:
            params_index (int): the index of the params
            address (int): the address in a basic block

        Returns:
            int: index of the basic block containing the specified address or -1 if not found
        """
        for idx, bb in enumerate(self.basic_blocks[params_index]):
            if bb.start <= address <= bb.stop:
                return idx
        return -1

    def get_instruction_type(self, entity) -> InstructionType:
        """
        Get the type of the instruction (fetch or use).

        Args:
            entity (PcodeOpAST | VarnodeAST): the entity of the instruction

        Returns:
            InstructionType: the type of the instruction
        """
        # TODO: set __stack_chk_fail type to NONE

        refined_pcode = (
            entity.getDef() if isinstance(entity, VarnodeAST) else entity
        )
        if not refined_pcode:
            return InstructionType.NONE

        refined_opcode = refined_pcode.getOpcode()

        # reverse to check the CALL opcode first
        for raw_pcode in reversed(self.get_raw_pcode(entity)):
            opcode = raw_pcode.getOpcode()
            if opcode == PcodeOp.CALL:
                function_addr = raw_pcode.getInput(0).getAddress()
                function_name = self.function_manager.getFunctionAt(
                    function_addr
                ).getName()
                if function_name in self.fetch_function_names:
                    return InstructionType.FETCH
                elif function_name in self.use_function_names:
                    return InstructionType.USE
            elif (
                opcode == PcodeOp.COPY
                or opcode == PcodeOp.STORE
                or opcode == PcodeOp.CBRANCH
            ):
                return InstructionType.USE
            elif refined_opcode not in [
                PcodeOp.PTRADD,
                PcodeOp.PTRSUB,
            ] and opcode in [
                PcodeOp.INT_ADD,
                PcodeOp.INT_SUB,
            ]:
                return InstructionType.NONE

        return InstructionType.FETCH

    def get_raw_pcode(self, entity) -> List[PcodeOp]:
        """
        Get the raw pcode of the specified entity.

        Args:
            entity (PcodeOpAST | VarnodeAST): the entity to get the raw pcode of

        Returns:
            List[PcodeOp]: list of raw pcodes
        """
        instruction = None
        if isinstance(entity, PcodeOpAST):
            instruction: List[PcodeOp] = getInstructionAt(
                entity.getSeqnum().getTarget()
            )
        elif isinstance(entity, VarnodeAST):
            instruction: List[PcodeOp] = getInstructionAt(entity.getPCAddress())

        if instruction:
            return instruction.getPcode()
        else:
            return []

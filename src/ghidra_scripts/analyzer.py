from dataclasses import dataclass
import logging
import os

from decompile_util import (
    SignatureChanger,
    Decompiler,
    INVOKE_COMMAND_FUNC_NAME,
    OPEN_SESSION_FUNC_NAME,
)


from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.block import CodeBlockImpl
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.database.function import FunctionDB
from ghidra.program.database import ProgramDB
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
    SequenceNumber,
)
from helpers import pp
from graphhelper import GraphHelper

################################################################################
# TYPING
################################################################################

from typing import List, Dict, Set, Tuple, Hashable, Any

################################################################################
# LOGGING
################################################################################

import logging

log = logging.getLogger(__name__)

################################################################################
# GLOBALS
################################################################################

PROGRAM: ProgramDB = getCurrentProgram()
DECOMPILER: Decompiler = Decompiler(PROGRAM)

################################################################################
# CODE
################################################################################

LVL = 0


class AnalyzerException(Exception):
    pass


@dataclass
class ParamSink:
    """Represents the output varnode of a PTRADD/PTRSUB where a TEE_Param is
    obtained from a TEEC_Param[]."""

    node_id: Hashable
    varnode: VarnodeAST
    param_idx: int


@dataclass
class ParamsArgConsumer:
    """Holds information to track `params` across function boundaries."""

    node_id: Hashable
    pcode: PcodeOp
    func: FunctionDB
    arg_idx: int


@dataclass
class DerefSink:
    """Represents a PcodeOp where a TEE_Param is used as a memref."""

    node_id: Hashable
    pcode: PcodeOp
    param_idx: int


@dataclass
class ParamConsumer:
    """Holds information to track `param.memref.buffer` across function
    boundaries."""

    node_id: Hashable
    pcode: PcodeOp
    func: FunctionDB
    arg_idx: int
    param_idx: int


class BaseAnalyzer:
    def __init__(
        self,
        func: FunctionDB,
        out_dir: str,
    ) -> None:
        # TODO: make class member
        self._program: ProgramDB = getCurrentProgram()
        self._ptr_size: int = self._program.getDefaultPointerSize()
        self._function_manager = self._program.getFunctionManager()
        self._block_model = BasicBlockModel(self._program)
        self._monitor = ConsoleTaskMonitor()
        self._decompiler: Decompiler = Decompiler(self._program)
        self._sig_changer = SignatureChanger(self._program)

        self._out_dir = out_dir

        # TODO: validate this for 64-bit targets
        self._param_size = self._ptr_size * 2
        self._func: FunctionDB = func

    def _trace_param_types_arg(
        self, param_types_varnode: VarnodeAST
    ) -> Tuple[
        List[Tuple[str, PcodeOp]], List[Tuple[PcodeOp, FunctionDB, int]]
    ]:
        """Populate existing analyzers in case `param_types` are passed to
        their function as an argument. Collect and return all nodes that
        compare the `param_types` (overapproximate checker nodes)."""
        checker_nodes: List[Tuple[str, PcodeOp]] = []
        caller_nodes: List[Tuple[PcodeOp, FunctionDB, int]] = []

        types_descendants_animator = self._collect_arg_descendants(
            param_types_varnode
        )

        types_descendants_animator.render(
            os.path.join(
                self._out_dir,
                f"{self._func.getName()}_param_types_descendants.pdf",
            )
        )

        log.debug(
            f"descendants: {types_descendants_animator.get_nodes().items()}"
        )

        # TODO: we need to _isolate_paths() here
        for node_id in types_descendants_animator.get_nodes().keys():
            node = types_descendants_animator.get_node(node_id)
            if "op" not in node:
                continue

            pcode: PcodeOp = node["op"]
            in_varnode: VarnodeAST = node["input"]

            log.debug(f"{node_id}: {pcode}")
            op: int = pcode.getOpcode()
            if op in [
                PcodeOp.INT_EQUAL,
                PcodeOp.INT_NOTEQUAL,
            ]:
                checker_nodes.append((node_id, pcode))
            elif op == PcodeOp.CBRANCH:
                # TODO: determine if execution correctly aborted and
                # BAD_PARAMETERS returned
                pass
            elif op == PcodeOp.COPY:
                pass
            elif op == PcodeOp.MULTIEQUAL:
                pass
            elif op == PcodeOp.CALL:
                # `param_types` passed as an argument to another function
                dst: VarnodeAST = pcode.getInput(0)
                slot: int = pcode.getSlot(in_varnode)
                assert slot > 0, ""
                idx = slot - 1
                func: Function = getFunctionAt(dst.getAddress())
                log.info(
                    f"`param_types` passed to {func.getName()} at idx {idx}"
                )
                # TODO: mark pcode as propagate/forward arg node
                # remember func and arg idx of param_types
                caller_nodes.append((pcode, func, idx))
            elif op == PcodeOp.RETURN:
                pass
            elif op == PcodeOp.INDIRECT:
                pass
            elif op == PcodeOp.CAST:
                pass
            elif op == PcodeOp.LOAD:
                pass
            elif op == PcodeOp.STORE:
                pass
            elif op == PcodeOp.INT_RIGHT:
                pass
            else:
                log.warn(f"Opcode {node['op']} not supported.")
        return checker_nodes, caller_nodes

    def _op2addr(self, pcode: PcodeOp) -> int:
        blocks = self._block_model.getCodeBlocksContaining(
            pcode.getSeqnum().getTarget(), self._monitor
        )
        assert len(blocks) == 1, f"Expected exactly one basic block: {blocks}"

        return blocks[0].getMinAddress().getOffset()

    def _trace_param(
        self, param_sink: ParamSink
    ) -> Tuple[List[DerefSink], List[ParamConsumer]]:
        param_descendants = self._collect_arg_descendants(param_sink.varnode)

        derefs: List[DerefSink] = []
        param_consumers: List[ParamConsumer] = []

        param_paths_animators = self._isolate_paths(param_descendants)

        for animator in param_paths_animators:
            tmp_derefs, tmp_param_consumers = self._find_derefs(
                animator, param_sink
            )
            derefs.extend(tmp_derefs)
            param_consumers.extend(tmp_param_consumers)

        return derefs, param_consumers

    def _trace_params_arg(
        self, params_varnode: VarnodeAST
    ) -> Tuple[List[ParamSink], List[ParamsArgConsumer]]:
        params_descendants = self._collect_arg_descendants(params_varnode)

        params_descendants.render(
            os.path.join(
                self._out_dir, f"{self._func.getName()}_params_descendants.svg"
            )
        )
        params: List[ParamSink] = []
        params_arg_consumers: List[ParamsArgConsumer] = []

        if len(params_descendants.get_nodes()) > 1:
            params_paths_animators = self._isolate_paths(params_descendants)

            for animator in params_paths_animators:
                self._chop_after_first_deref(
                    params_varnode, animator, params, params_arg_consumers
                )

        return params, params_arg_consumers

    def _collect_arg_descendants(self, arg_varnode: VarnodeAST) -> GraphHelper:
        animator = GraphHelper()
        instance_id: int = arg_varnode.getUniqueId()
        label = f"{arg_varnode.getHigh().getName()}\n"
        label += f"{arg_varnode}"
        animator.add_node(instance_id, label=label)

        visited_descendants = {}
        visited_descendants[instance_id] = True

        self._traverse_varnode(
            animator, instance_id, arg_varnode, visited_descendants
        )

        # update each node label for visualization
        for node_id, node_data in animator.get_nodes().items():
            if "op" in node_data:
                op: PcodeOpAST = node_data["op"]

                label = f"{op.getSeqnum().getTarget().getOffset():#x}:\n\n"
                label += f"{op.getOutput()}\n"
                label += f"{op.getMnemonic()}\n"

                for in_idx in range(op.getNumInputs()):
                    label += f"{op.getInput(in_idx)}\n"

                animator.update_label(node_id, label=label)

        return animator

    def _traverse_varnode(
        self,
        animator: GraphHelper,
        parent_id: Hashable,
        in_varnode: VarnodeAST,
        visited: Dict[str, bool],
    ) -> None:
        global LVL
        # print("\t" * LVL + str(instance))

        # get an interator to all `PcodeOpAST` (~Pcode Operations) that take
        # `instance` as an input
        descendants: List[PcodeOpAST] = in_varnode.getDescendants()

        for pcode_op in descendants:
            # print(f"pcode: {pcode_op}")
            out_varnode: VarnodeAST = pcode_op.getOutput()

            node: SequenceNumber = pcode_op.getSeqnum()
            if not out_varnode:
                visited[node] = True
            else:
                if node not in visited:
                    visited[node] = True
                    # print("\t" * LVL + str(desc))
                    LVL += 1
                    self._traverse_varnode(animator, node, out_varnode, visited)
                    LVL -= 1

            animator.add_edge(parent_id, node)
            node: Dict[str, object] = animator.get_node(node)
            node["input"]: VarnodeAST = in_varnode
            node["op"]: PcodeOpAST = pcode_op
            node["output"]: VarnodeAST = out_varnode

    def _collect_paths(
        self,
        animator: GraphHelper,
        node=None,
        path_nodes=None,
        paths_collection=None,
    ):
        if path_nodes is None:
            path_nodes = list()
        if paths_collection is None:
            paths_collection = list()
        if node is None:
            node = animator._entry_node

        # append the current node
        path_nodes.append(node)

        if len(list(animator._ga.neighbors(node))) == 0:
            paths_collection.append(path_nodes)

        for n in animator._ga.neighbors(node):
            if n not in path_nodes:
                self._collect_paths(
                    animator, n, path_nodes.copy(), paths_collection
                )

        return paths_collection

    def _isolate_paths(self, desc_animator: GraphHelper) -> List[GraphHelper]:
        animators: List[GraphHelper] = []

        paths_collection = self._collect_paths(desc_animator)

        for paths in paths_collection:
            anim = GraphHelper()
            animators.append(anim)

            for idx in range(len(paths) - 1):
                anim.add_edge(paths[idx], paths[idx + 1])

        for animator in animators:
            for node_id in animator._ga.nodes:
                o_node_data = desc_animator.get_node(node_id)
                # propagate input/output/op to node
                node_data = animator.get_node(node_id)
                # TODO: maybe point to the same dicts for the same node ids
                # so that we can colorize/annotate across animators?
                node_data.update(o_node_data)
                if "op" in node_data:
                    label = f"{node_id}\n\n"
                    in_varnode = node_data["input"]
                    out_varnode = node_data["output"]
                    op = node_data["op"]
                    label += f"{in_varnode}\n"
                    label += f"{op.getSeqnum().getTarget().getOffset():#x}: "
                    label += f"{op}\n"
                    if out_varnode:
                        label += f"{out_varnode}\n"
                    animator.update_label(node_id, label=label)
        return animators

    def _chop_after_first_deref(
        self,
        varnode: VarnodeAST,
        animator: GraphHelper,
        params: List[Tuple[str, VarnodeAST]],
        params_arg_consumers: List[Tuple[PcodeOp, FunctionDB, int]],
    ) -> None:
        global_offset: int = 0

        node_id = varnode.getUniqueId()
        while True:
            nodes = animator.neighbors(node_id)

            if not nodes:
                break

            if len(nodes) > 1:
                raise AnalyzerException("The path should not contain branches.")

            node_id = nodes[0]
            node = animator.get_node(node_id)

            if "op" not in node:
                # We require that all nodes, except of the entry node have
                # PCode Operations.
                raise AnalyzerException("Node is missing PCode Operation.")

            pcode: PcodeOp = node["op"]
            opcode: int = pcode.getOpcode()
            new_param_sink: ParamSink = None

            in_varnode = node["input"]
            if opcode == PcodeOp.PTRSUB:
                input0 = pcode.getInput(0)
                input1 = pcode.getInput(1)
                output = pcode.getOutput()

                # input1 should be a constant offset
                assert input1.isConstant(), "Expected input1 to be constant"
                offset: int = input1.getOffset()
                global_offset += offset
                slot: int = pcode.getSlot(in_varnode)
                assert slot == 0, "Expected in_varnode in slot 0"
            elif opcode == PcodeOp.PTRADD:
                input0 = pcode.getInput(0)  # base
                input1 = pcode.getInput(1)  # off
                input2 = pcode.getInput(2)  # sz
                output = pcode.getOutput()
                # input1 should be a constant offset
                assert input1.isConstant(), "Expected input1 to be constant"
                offset1: int = input1.getOffset()
                assert input2.isConstant(), "Expected input2 to be constant"
                offset2: int = input2.getOffset()
                global_offset += offset1 * offset2
            elif opcode == PcodeOp.LOAD:
                input0 = pcode.getInput(0)
                input1 = pcode.getInput(1)
                output: VarnodeAST = pcode.getOutput()
                # print(f"PcodeOp.LOAD: {output}")
                # print(f"deref @ nodeid: {node_id}")
                new_param_sink = ParamSink(node_id, output, None)
                break
            elif opcode == PcodeOp.STORE:
                output = pcode.getOutput()
                # print(f"PcodeOp.STORE: {output}")
            elif opcode == PcodeOp.CALL:
                dst: VarnodeAST = pcode.getInput(0)
                slot: int = pcode.getSlot(in_varnode)
                assert slot > 0, ""
                idx = slot - 1
                func: Function = getFunctionAt(dst.getAddress())
                # print(f"`params` passed to {func.getName()} at arg idx {idx}")
                params_arg_consumers.append(
                    ParamsArgConsumer(node_id, pcode, func, idx)
                )
                break
            elif opcode == PcodeOp.RETURN:
                pass
            elif opcode == PcodeOp.CAST:
                pass
            elif opcode == PcodeOp.INDIRECT:
                pass
            elif opcode == PcodeOp.COPY:
                pass
            elif opcode == PcodeOp.PIECE:
                pass
            elif opcode == PcodeOp.MULTIEQUAL:
                pass
            elif opcode == PcodeOp.INT_ADD:
                input0 = pcode.getInput(0)
                input1 = pcode.getInput(1)  # off
                output = pcode.getOutput()
                assert input1.isConstant(), "Expected input1 to be constant"
                global_offset += input1.getOffset()
            else:
                raise NotImplementedError(
                    f"Implement case for {pcode.getMnemonic()}"
                )

        # print(f"global_offset: {global_offset}")

        # determine param idx
        if (global_offset % self._param_size) == 0:
            param_idx = global_offset // self._param_size
            log.info(f"animator for param_idx {param_idx}")
            if new_param_sink:
                new_param_sink.param_idx = param_idx
                params.append(new_param_sink)
        return

    def _find_derefs(
        self, animator: GraphHelper, param_sink: ParamSink
    ) -> Tuple[List[DerefSink], List[ParamConsumer]]:
        """The input varnode of the first pcode node represents either a memory
        reference or a value. This function walks through all the usages of this
        input varnode and determines if it is ever derefernece (used as a
        memref).
        """

        # TODO: ensure that the first pcode node only has one input varnode
        # TODO: ensure that the nodes are ordered according to their DF dependency
        print(f"Checking memref for path starting with {animator._entry_node}")

        tainted: Set[Varnode] = set()
        tainted.add(param_sink.varnode)

        deref_nodes: List[DerefSink] = []
        param_consumer: List[ParamConsumer] = []

        for idx, node_id in enumerate(animator.get_nodes()):
            node: Dict[str, object] = animator.get_node(node_id)

            if idx == 0 and "op" not in node:
                continue

            pcode: PcodeOp = node["op"]

            print(
                f"{pcode.getSeqnum().getTarget().getOffset():#x}: {pcode} (ID: {node_id})"
            )
            opcode: int = pcode.getOpcode()

            if idx == 0:
                tainted.add(node["tainted"])

            if opcode == PcodeOp.CALL:
                addr = pcode.getInput(0).getAddress()  # callee addr
                callee_func = self._function_manager.getFunctionAt(addr)
                in_varnode = node["input"]

                func_name = f"{addr}"
                if callee_func:
                    func_name = callee_func.getName()

                slot: int = pcode.getSlot(in_varnode)
                assert slot > 0, ""

                arg_idx = slot - 1

                print(f"buffer passed to {func_name} as {arg_idx} param")

                if self.is_known_memref(func_name, arg_idx):
                    # function is a known memref function (memcpy, TEE_MemMove etc..)
                    # add a dereference
                    log.debug(
                        f"deref found in known function: {func_name}, {arg_idx}"
                    )
                    deref_nodes.append(
                        DerefSink(node_id, pcode, param_sink.param_idx)
                    )
                else:
                    param_consumer.append(
                        ParamConsumer(
                            node_id,
                            pcode,
                            callee_func,
                            arg_idx,
                            param_sink.param_idx,
                        )
                    )
                break
            elif opcode == PcodeOp.CAST:
                in0: Varnode = pcode.getInput(0)
                out: Varnode = pcode.getOutput()
                tainted.add(in0)
                tainted.add(out)
            elif opcode == PcodeOp.INT_EQUAL:
                pass
            elif opcode == PcodeOp.INT_NOTEQUAL:
                pass
            elif opcode == PcodeOp.CBRANCH:
                pass
            elif opcode == PcodeOp.PTRADD:
                input0 = pcode.getInput(0)  # base
                input1 = pcode.getInput(1)  # off
                input2 = pcode.getInput(2)  # sz
                output = pcode.getOutput()

                offset1: int = input1.getOffset()
                offset2: int = input2.getOffset()
                tainted.add(output)
            elif opcode == PcodeOp.PTRSUB:
                input0 = pcode.getInput(0)
                input1 = pcode.getInput(1)
                output = pcode.getOutput()

                # input1 should be a constant offset
                assert input1.isConstant(), "Expected input1 to be constant"
                offset: int = input1.getOffset()
                tainted.add(output)
            elif opcode == PcodeOp.LOAD:
                in0: Varnode = pcode.getInput(0)  # Constant ID of space
                in1: Varnode = pcode.getInput(1)  # pointer offset to data
                if in1 in tainted:
                    deref_nodes.append(
                        DerefSink(node_id, pcode, param_sink.param_idx)
                    )
                    break
            elif opcode == PcodeOp.STORE:
                in0: Varnode = pcode.getInput(0)  # Constant ID of space
                in1: Varnode = pcode.getInput(1)  # pointer offset to data
                if in1 in tainted:
                    deref_nodes.append(
                        DerefSink(node_id, pcode, param_sink.param_idx)
                    )
                    break
            else:
                print(f"Implement case for {pcode.getMnemonic()}")
                # raise NotImplementedError(f"Implement case for {pcode.getMnemonic()}")
        return deref_nodes, param_consumer

    def prune_deref_subtree(self):
        bfs_nodes = self._animator.bfs(self._entry_node)
        derefs = []
        for node_id in bfs_nodes:
            node = self._animator.get_node(node_id)
            if "op" in node and node["op"].getOpcode() in [PcodeOp.PTRSUB]:
                derefs.append(node_id)
        print(derefs)

    def is_known_memref(self, func_name, arg_idx):
        known_memrefs = {
            "memcpy": [0, 1],
            "memmove": [0, 1],
            "memset": [0, 1],
            "strcpy": [0, 1],
            "strncpy": [0, 1],
            "memset": [0],
            "strlen": [0],
            "memcmp": [0, 1],
            "strcmp": [0, 1],
            "TEE_MemMove": [0, 1],
            "TEE_MemCompare": [0, 1],
            "TEE_MemFill": [0],
            "TEE_CheckMemoryAccessRights": [1],
        }
        if func_name in known_memrefs:
            if arg_idx in known_memrefs[func_name]:
                return True
        return False

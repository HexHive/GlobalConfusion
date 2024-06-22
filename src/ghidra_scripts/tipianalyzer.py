import json
import copy
import logging
import os

import helpers

from analyzer import (
    BaseAnalyzer,
    ParamSink,
    ParamsArgConsumer,
    DerefSink,
    ParamConsumer,
    AnalyzerException,
)
from decompile_util import (
    Decompiler,
)


from ghidra.program.database.function import FunctionDB
from ghidra.program.database import ProgramDB
from ghidra.program.model.pcode import (
    VarnodeAST,
    PcodeOp,
)
from graphhelper import GraphHelper

################################################################################
# TYPING
################################################################################

from typing import List, Dict, Set, Tuple, Any

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


class MemrefAnalyzerResult:
    MEMREF_NOT_DOMINATED = -2
    NO_CHECK_MEMREF = -1
    CHECK_OK = 0
    NO_CHECK_NO_MEMREF = 1
    FUNCTION_NOT_FOUND = 2
    MULTIPLE_CANDIDATES_FOR_FUNCTION = 3
    CHECK_NO_MEMREF = 4
    NON_GP_COMPLIANT = 5


class MemrefAnalyzerReport:
    _res2str = {
        MemrefAnalyzerResult.MEMREF_NOT_DOMINATED: "memref found, not dominated",
        MemrefAnalyzerResult.NO_CHECK_MEMREF: "no check, memref found",
        MemrefAnalyzerResult.CHECK_OK: "check ok",
        MemrefAnalyzerResult.NO_CHECK_NO_MEMREF: "no check, no memref found",
        MemrefAnalyzerResult.FUNCTION_NOT_FOUND: "function not found",
        MemrefAnalyzerResult.MULTIPLE_CANDIDATES_FOR_FUNCTION: "multiple candidates for function found",
        MemrefAnalyzerResult.CHECK_NO_MEMREF: "checks present, no memref found",
        MemrefAnalyzerResult.NON_GP_COMPLIANT: "not GP compliant",
    }

    def __init__(self, result: int):
        self._result: int = result

    def describe(self) -> Dict[str, Any]:
        return {
            "result": self._result,
            "desc": MemrefAnalyzerReport._res2str[self._result],
        }

    def __str__(self):
        return json.dumps(self.describe(), indent=4)

    def __repr__(self):
        return self.__str__()


class TypeCheckAnalyzer(BaseAnalyzer):
    def __init__(
        self,
        func: FunctionDB,
        param_types_args: List[VarnodeAST],
        params_args: List[VarnodeAST],
        params: List[ParamSink],
        out_dir: str,
    ) -> None:

        super().__init__(func, out_dir)

        # all the initial varnodes derived from `param_types`
        self._param_types_args = param_types_args
        # all the initial varnodes derived from `params`
        self._params_args = params_args
        # all the initial varnodes derived from individual param instances
        self._params = params if params else []

        self.analyzers: List[TypeCheckAnalyzer] = []
        self._dec_func = None  # populated during analysis

    def analyze(self, current_depth, max_recursion_depth) -> Dict[str, str]:
        log.debug(
            f"Starting analysis of {self._func.getName()}@{self._func.getEntryPoint()}"
        )

        self._cfg: GraphHelper = helpers.cfg(
            self._program, self._func, disasm=True
        )

        ########################################################################
        # taint tracking of all param_type taints
        ########################################################################

        checker_nodes: List[Tuple[str, PcodeOp]] = []
        param_types_arg_consumers: List[Tuple[PcodeOp, FunctionDB, int]] = []

        for varnode in self._param_types_args:
            tmp_checker_nodes, tmp_caller_nodes = self._trace_param_types_arg(
                varnode
            )
            checker_nodes.extend(tmp_checker_nodes)
            param_types_arg_consumers.extend(tmp_caller_nodes)

        log.debug(f"checker nodes: {checker_nodes}")
        log.debug(f"caller nodes: {param_types_arg_consumers}")

        ########################################################################
        # taint tracking of all param array taints
        ########################################################################

        params: List[ParamSink] = []
        params_arg_consumers: List[ParamsArgConsumer] = []

        for varnode in self._params_args:
            tmp_params, tmp_params_consumers = self._trace_params_arg(varnode)
            params.extend(tmp_params)
            params_arg_consumers.extend(tmp_params_consumers)

        self._params.extend(params)

        ########################################################################
        # taint tracking of all param taints
        ########################################################################

        param_derefs: List[DerefSink] = []
        param_consumers: List[ParamConsumer] = []
        for param in self._params:
            tmp_derefs, tmp_consumers = self._trace_param(param)
            param_derefs.extend(tmp_derefs)
            param_consumers.extend(tmp_consumers)

        ########################################################################
        # now we're left with param array and param tainted calls, and derefs.
        ########################################################################

        log.info(f"checkers: {checker_nodes}")
        log.info(f"derefs: {param_derefs}")
        if len(checker_nodes) == 0 and len(param_derefs) > 0:
            # no checker nodes and memref usage
            report: MemrefAnalyzerReport = MemrefAnalyzerReport(
                MemrefAnalyzerResult.NO_CHECK_MEMREF
            )

        elif len(checker_nodes) == 0 and len(param_derefs) == 0:
            # no checker nodes and no memref usage
            report: MemrefAnalyzerReport = MemrefAnalyzerReport(
                MemrefAnalyzerResult.NO_CHECK_NO_MEMREF
            )
        elif len(checker_nodes) > 0 and len(param_derefs) == 0:
            report: MemrefAnalyzerReport = MemrefAnalyzerReport(
                MemrefAnalyzerResult.CHECK_NO_MEMREF
            )
        elif len(checker_nodes) > 0 and len(param_derefs) > 0:
            unchecked_derefs: List[str] = list()
            report = MemrefAnalyzerReport(MemrefAnalyzerResult.CHECK_OK)

            for deref in param_derefs:
                checked: bool = self._is_checked(checker_nodes, deref.pcode)
                if not checked:
                    report = MemrefAnalyzerReport(
                        MemrefAnalyzerResult.MEMREF_NOT_DOMINATED
                    )

        # TODO: handle else case to avoid runtime exception here
        reports = {
            self._func.getName(): {
                "desc": report.describe(),
                "children": dict(),
            }
        }

        # TODO: detect recursive calls

        # TODO: report if func is external
        # func.isExternal()

        # TODO: avoid duplicate tracing by caching already analyzed functions

        args_by_callsite = {}
        for consumer in param_types_arg_consumers:
            if len(consumer) != 3:
                log.debug(f"Error: {consumer}")
            callsite: PcodeOp = consumer[0]
            if self._is_checked(checker_nodes, callsite):
                continue
            func = consumer[1]
            arg_idx = consumer[2]
            if callsite not in args_by_callsite:
                args_by_callsite[callsite] = ([], [], [])
            if func.getParameterCount() >= arg_idx + 1:
                log.info(
                    f"Adding func {func.getName()} called by {callsite} to analysis queue"
                )
                dec_func = DECOMPILER.decompile_function(func)
                varnode = DECOMPILER.get_argument_varnode(func, arg_idx)
                args_by_callsite[callsite][0].append(varnode)
            else:
                log.warn(
                    f"Func {func.getName()} does not consume arg at idx {arg_idx}"
                )

        for consumer in params_arg_consumers:
            callsite = consumer.pcode
            if self._is_checked(checker_nodes, callsite):
                continue
            func = consumer.func
            if callsite not in args_by_callsite:
                args_by_callsite[callsite] = ([], [], [])
            if func.getParameterCount() >= consumer.arg_idx + 1:
                log.info(
                    f"Adding func {func.getName()} called by {callsite} to analysis queue"
                )
                dec_func = DECOMPILER.decompile_function(func)
                varnode = DECOMPILER.get_argument_varnode(
                    func, consumer.arg_idx
                )
                args_by_callsite[callsite][1].append(varnode)
            else:
                log.warn(
                    f"Func {func.getName()} does not consume arg at idx {consumer.arg_idx}"
                )

        for consumer in param_consumers:
            callsite = consumer.pcode
            try:
                if self._is_checked(checker_nodes, callsite):
                    continue
            except:
                # TODO: inspect this case further instead of skipping
                continue
            func = consumer.func
            if callsite not in args_by_callsite:
                args_by_callsite[callsite] = ([], [], [])
            if func.getParameterCount() >= consumer.arg_idx + 1:
                log.info(
                    f"Adding func {func.getName()} called by {callsite} to analysis queue"
                )
                dec_func = DECOMPILER.decompile_function(func)
                varnode = DECOMPILER.get_argument_varnode(
                    func, consumer.arg_idx
                )
                args_by_callsite[callsite][2].append(
                    ParamSink(
                        varnode.getUniqueId(), varnode, consumer.param_idx
                    )
                )
            else:
                log.warn(
                    f"Func {func.getName()} does not consume arg at idx {consumer.arg_idx}"
                )

        if current_depth + 1 < max_recursion_depth:
            # limit the recursion depth
            analyzers: List[TypeCheckAnalyzer] = []
            for pcode, args in args_by_callsite.items():
                dst: VarnodeAST = pcode.getInput(0)
                func: Function = getFunctionAt(dst.getAddress())
                analyzers.append(
                    TypeCheckAnalyzer(
                        func, args[0], args[1], args[2], self._out_dir
                    )
                )

            for analyzer in analyzers:
                # if analyzer._func.getName() == "requestReset":
                reports[self._func.getName()]["children"].update(
                    analyzer.analyze(
                        current_depth=current_depth + 1,
                        max_recursion_depth=max_recursion_depth,
                    )
                )
        else:
            log.debug("not analyzing children due to recursion")
        self._cfg.render(
            os.path.join(self._out_dir, f"{self._func.getName()}_cfg.svg")
        )

        return reports

    def _is_checked(self, checker_nodes, node):
        """Copy cfg for the current function, remove checker nodes, and determine
        if there is still a path from the entry point to the deref node."""
        checked: bool = True
        deref_bb_start = hex(self._op2addr(node))
        cfg = copy.deepcopy(self._cfg)
        all_checker_nodes_in_cfg = []

        for _, check_op in checker_nodes:
            check_bb_start = hex(self._op2addr(check_op))
            # take care of the case where deref and check are in the same bb
            if check_bb_start == deref_bb_start:
                if (
                    check_op.getSeqnum().getTarget().getOffset()
                    < node.getSeqnum().getTarget().getOffset()
                ):
                    checked = True
                else:
                    checked = False
                return checked
            all_checker_nodes_in_cfg.append(check_bb_start)

        func_entry_node = list(cfg.get_nodes())[0]
        if func_entry_node in all_checker_nodes_in_cfg:
            # edge case where a checker node is the entry node.
            # the entry node dominates all nodes in the cfg, hence the check is
            # ok
            checked = True
            return checked

        cfg.remove_nodes(all_checker_nodes_in_cfg)

        if cfg.has_path(func_entry_node, deref_bb_start):
            checked = False
            path = cfg.shortest_path(func_entry_node, deref_bb_start)
            log.info(f"{func_entry_node} path: {path}")
        return checked

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
                print(f"PcodeOp.LOAD: {output}")
                print(f"deref @ nodeid: {node_id}")
                new_param_sink = ParamSink(node_id, output, None)
                break
            elif opcode == PcodeOp.STORE:
                output = pcode.getOutput()
                print(f"PcodeOp.STORE: {output}")
            elif opcode == PcodeOp.CALL:
                dst: VarnodeAST = pcode.getInput(0)
                slot: int = pcode.getSlot(in_varnode)
                assert slot > 0, ""
                idx = slot - 1
                func: Function = getFunctionAt(dst.getAddress())
                print(f"`params` passed to {func.getName()} at arg idx {idx}")
                params_arg_consumers.append(
                    ParamsArgConsumer(node_id, pcode, func, idx)
                )
                break
            elif opcode == PcodeOp.RETURN:
                pass
            elif opcode == PcodeOp.CAST:
                pass
            elif opcode == PcodeOp.INT_EQUAL:
                pass
            elif opcode == PcodeOp.INT_NOTEQUAL:
                pass
            elif opcode == PcodeOp.CBRANCH:
                pass
            elif opcode == PcodeOp.INDIRECT:
                pass
            elif opcode == PcodeOp.COPY:
                pass
            elif opcode == PcodeOp.PIECE:
                pass
            elif opcode == PcodeOp.MULTIEQUAL:
                pass
            elif opcode == PcodeOp.BOOL_OR:
                pass
            elif opcode == PcodeOp.BOOL_AND:
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

        print(f"global_offset: {global_offset}")

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

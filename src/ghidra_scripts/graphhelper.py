from __future__ import annotations
import networkx as nx
from networkx.drawing.nx_agraph import to_agraph
from networkx import MultiDiGraph
from networkx.algorithms.dominance import immediate_dominators
from networkx.algorithms.shortest_paths import has_path, shortest_path

################################################################################
# LOGGING
################################################################################

import logging

log = logging.getLogger(__name__)

################################################################################
# TYPING
################################################################################

from typing import Dict, List, Any
from collections.abc import Iterator

################################################################################
# CODE
################################################################################


class GraphHelperException(Exception):
    pass


class GraphHelper(object):
    """Objects of this class represent a graph. The class provides various
    methods to create, manage, and visualize graphs.
    """

    def __init__(self):
        self._ga = MultiDiGraph()
        self._entry_node = None
        self.info = dict()

    def update_label(self, node: object, label: str) -> None:
        self.add_node(node, label=label)

    def update_color(self, node: object, color: str) -> None:
        self.add_node(node, color=color)

    def has_path(self, src_node: object, dst_node: object) -> bool:
        return has_path(self._ga, src_node, dst_node)

    def shortest_path(self, src_node: object, dst_node: object) -> List[object]:
        return shortest_path(self._ga, src_node, dst_node)

    def get_node(self, node: object) -> Dict[str, object]:
        return self._ga.nodes[node]

    def get_nodes(self) -> Dict[Any]:
        return self._ga.nodes

    def add_node(self, new_node: object, **kwargs) -> None:
        if len(self._ga.nodes) == 0:
            self._entry_node = new_node

        if new_node not in self._ga.nodes:
            self._ga.add_node(new_node)

        for k, v in kwargs.items():
            self._ga.nodes[new_node][k] = v

    def remove_nodes(self, nodes: List[object]) -> None:
        self._ga.remove_nodes_from(nodes)

    def neighbors(self, node: object) -> List[object]:
        nodes: Iterator[object] = self._ga.neighbors(node)
        return [n for n in nodes]

    def has_nodes(self) -> bool:
        return True if len(self._ga.nodes) else False

    def add_edge(
        self, src_node: object, dst_node: object, color: str = "black"
    ) -> None:
        self._ga.add_edge(src_node, dst_node, color=color)

    def bfs(self, src_node: object):
        return sorted(list(nx.bfs_tree(self._ga, src_node)))

    def dfs(self, src_node: object):
        return [
            (n[0], n[1])
            for n in nx.dfs_labeled_edges(self._ga, source=src_node)
            if n[2] == "forward" and n[0] != n[1]
        ]

    def dom(self) -> GraphHelper:
        """Create another animator representing the dominator tree for this
        animator.

        Raises:
            AnimatorException: Exception raised when the animator is used in a
            wrong way.

        Returns:
            Animator: The animator containing the dominator tree.
        """

        keys = sorted(self._ga.nodes, key=lambda x: int(x, 16))
        if len(keys) == 0:
            return None

        # obtain the edges from the dominator tree, starting with the function
        # entrypoint node.
        first_node = keys[0]
        print("first_node", first_node)
        dom_edges = sorted(
            [
                (b, a)
                for a, b in immediate_dominators(self._ga, first_node).items()
            ]
        )

        # create the animator object returned from this function
        dom_anim = GraphHelper()

        # initialize the DiGraph
        dom_tree = nx.DiGraph(dom_edges)
        dom_anim._ga = dom_tree

        # initialize the animator's nodes
        dom_nodes = {}
        for a, b in dom_edges:
            dom_nodes[a] = {}
            dom_nodes[b] = {}
        dom_anim._ga.add_nodes_from(dom_nodes)
        return dom_anim

    def render(self, filename: str) -> None:
        agraph = to_agraph(self._ga)
        agraph.node_attr["shape"] = "square"
        agraph.node_attr["nojustify"] = "false"
        agraph.draw(filename, prog="dot")

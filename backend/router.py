"""Route table and node blocking decisions."""

from __future__ import annotations

from . import config

DEFAULT_ROUTE = ("sender", "node1", "node2", "node3", "receiver")
_blocked_nodes: set[str] = set()


def reset_routes() -> None:
    _blocked_nodes.clear()


def block_node(node_name: str) -> None:
    if node_name in DEFAULT_ROUTE:
        _blocked_nodes.add(node_name)


def unblock_node(node_name: str) -> None:
    _blocked_nodes.discard(node_name)


def get_active_route() -> list[str]:
    return [node for node in DEFAULT_ROUTE if node not in _blocked_nodes]


def get_next_hop(source: str) -> str | None:
    active_route = get_active_route()
    if source not in active_route:
        return None
    source_index = active_route.index(source)
    if source_index + 1 >= len(active_route):
        return None
    return active_route[source_index + 1]


def get_node_statuses() -> dict[str, dict[str, object]]:
    active_route = get_active_route()
    statuses: dict[str, dict[str, object]] = {}
    for node in DEFAULT_ROUTE:
        statuses[node] = {
            "status": "blocked" if node in _blocked_nodes else "active",
            "nextHop": get_next_hop(node),
            "port": config.NODE_PORTS.get(node),
            "inRoute": node in active_route,
        }
    return statuses


"""Generic depth-first walker over esprima AST nodes."""
def walk(node, visitor):
    """Depth-first AST walk. Calls visitor(node) for every node."""
    if node is None:
        return
    if not hasattr(node, 'type'):
        return
    try:
        visitor(node)
    except Exception:
        pass
    for key in vars(node):
        child = getattr(node, key, None)
        if child is None:
            continue
        if isinstance(child, list):
            for item in child:
                if hasattr(item, 'type'):
                    walk(item, visitor)
        elif hasattr(child, 'type'):
            walk(child, visitor)

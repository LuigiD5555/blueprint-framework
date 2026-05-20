"""Python AST scanner for BPFW MVP Catalog Mode."""

import ast
from pathlib import Path
from typing import Any, Dict, List, Optional

from bpfw.catalog.models import DiscoveredCodeUnit, ScanResult
from bpfw.catalog.review_order import order_blocks_for_review
from bpfw.reports.finding import Finding


def scan_python_project(
    project_root: Path,
    source_roots: List[str],
    ignored_paths: List[str],
) -> ScanResult:
    """
    Scan Python project using AST parsing.

    Args:
        project_root: Root directory of the project.
        source_roots: List of source root directories relative to project_root.
        ignored_paths: List of path patterns to ignore.

    Returns:
        ScanResult containing discovered code units and any findings.
    """
    discovered_units: List[DiscoveredCodeUnit] = []
    findings: List[Finding] = []

    for source_root in source_roots:
        source_root_path = project_root / source_root

        # Ignore missing source roots silently
        if not source_root_path.exists():
            continue

        if not source_root_path.is_dir():
            continue

        # Recursively scan .py files
        for py_file in source_root_path.rglob("*.py"):
            file_path = py_file.relative_to(project_root)

            # Skip if any path part matches ignored paths
            if _is_path_ignored(file_path, ignored_paths):
                continue

            # Scan the file
            file_units, file_findings = _scan_python_file(
                project_root,
                py_file,
                file_path,
            )
            discovered_units.extend(file_units)
            findings.extend(file_findings)

    # Sort discovered units using dependency-first topological ordering.
    # Dependencies are reviewed before dependents for better context.
    discovered_units = order_blocks_for_review(discovered_units)

    return ScanResult(
        discovered_units=discovered_units,
        findings=findings,
    )


def _is_path_ignored(file_path: Path, ignored_paths: List[str]) -> bool:
    """
    Check if a file path should be ignored.

    Args:
        file_path: Relative file path to check.
        ignored_paths: List of path patterns to ignore.

    Returns:
        True if the path should be ignored, False otherwise.
    """
    path_parts = file_path.parts

    for ignored in ignored_paths:
        if ignored in path_parts:
            return True

    return False


def _scan_python_file(
    project_root: Path,
    file_path: Path,
    relative_path: Path,
) -> tuple[List[DiscoveredCodeUnit], List[Finding]]:
    """
    Scan a single Python file for code units.

    Args:
        project_root: Root directory of the project.
        file_path: Absolute path to the Python file.
        relative_path: Relative path from project root.

    Returns:
        Tuple of (discovered units, findings).
    """
    discovered_units: List[DiscoveredCodeUnit] = []
    findings: List[Finding] = []

    # Read file with UTF-8 encoding
    try:
        file_content = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        findings.append(
            Finding(
                source="bpfw",
                code="PYTHON_READ_ERROR",
                severity="block",
                message="Could not read file with UTF-8 encoding",
                path=str(relative_path),
            )
        )
        return discovered_units, findings

    # Parse AST
    try:
        tree = ast.parse(file_content, filename=str(file_path))
    except SyntaxError as e:
        findings.append(
            Finding(
                source="bpfw",
                code="PYTHON_PARSE_ERROR",
                severity="block",
                message="BPFW could not parse this Python file.",
                path=str(relative_path),
                evidence={
                    "line": e.lineno,
                    "offset": e.offset,
                },
            )
        )
        return discovered_units, findings

    # Extract imports from the module
    imports = _extract_imports(tree)

    # Extract module path
    module = _derive_module_path(relative_path)

    discovered_units.extend(
        _extract_code_units(
            nodes=tree.body,
            file_path=str(relative_path),
            module=module,
            imports=imports,
            parent_symbols=[],
            parent_kind=None,
        )
    )

    return discovered_units, findings


def _extract_code_units(
    nodes: List[ast.stmt],
    file_path: str,
    module: str,
    imports: List[str],
    parent_symbols: List[str],
    parent_kind: str | None,
) -> List[DiscoveredCodeUnit]:
    """Extract top-level and nested code units from AST nodes."""

    discovered_units: List[DiscoveredCodeUnit] = []
    for node in nodes:
        if isinstance(node, ast.ClassDef):
            if node.name.startswith("_"):
                continue
            # Filter out data classes (classes with no instance methods)
            if _is_data_class(node):
                continue
            # Filter out protocols and abstract classes
            if _is_protocol_or_abstract_class(node):
                continue

            symbol_parts = parent_symbols + [node.name]
            unit = _extract_class_unit(
                node=node,
                file_path=file_path,
                module=module,
                imports=imports,
                symbol=".".join(symbol_parts),
                symbol_type=_class_symbol_type(parent_symbols),
            )
            if unit:
                discovered_units.append(unit)
            discovered_units.extend(
                _extract_code_units(
                    nodes=node.body,
                    file_path=file_path,
                    module=module,
                    imports=imports,
                    parent_symbols=symbol_parts,
                    parent_kind="class",
                )
            )
            continue

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Filter out private methods (except dunder methods)
            if node.name.startswith("_") and not (
                node.name.startswith("__") and node.name.endswith("__")
            ):
                continue
            # Filter out nested functions in decorators
            if _is_decorator_nested_function(node, parent_kind, parent_symbols):
                continue
            # Filter out tiny nested functions (< 5 lines of code)
            if parent_kind == "function" and _is_tiny_nested_function(node):
                continue
            # Filter out trivial methods (getters/setters with minimal logic)
            if parent_kind == "class" and _is_trivial_method(node):
                continue
            # Filter out property-like methods in schema.py

            symbol_parts = parent_symbols + [node.name]
            if _should_discover_function(node=node, parent_kind=parent_kind, module=module):
                unit = _extract_function_unit(
                    node=node,
                    file_path=file_path,
                    module=module,
                    imports=imports,
                    symbol=".".join(symbol_parts),
                    symbol_type=_function_symbol_type(
                        parent_symbols=parent_symbols,
                        parent_kind=parent_kind,
                    ),
                )
                if unit:
                    discovered_units.append(unit)
            discovered_units.extend(
                _extract_code_units(
                    nodes=node.body,
                    file_path=file_path,
                    module=module,
                    imports=imports,
                    parent_symbols=symbol_parts,
                    parent_kind="function",
                )
            )

    return discovered_units


def _is_trivial_method(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """
    Check if a method is trivial (getter/setter with minimal logic).
    A method is considered trivial if:
    - It has less than 3 lines of actual code (excluding decorators and docstring)
    - It doesn't contain complex logic (loops, conditions, try/except)
    Args:
        node: AST FunctionDef or AsyncFunctionDef node.
        Returns:
        True if the method is trivial, False otherwise.
    """
    # Count actual code lines (excluding decorators and docstring)
    code_lines = 0
    for stmt in node.body:
        # Skip docstring if it's the first statement
        if code_lines == 0 and isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
            if isinstance(stmt.value.value, str):
                continue

        code_lines += 1

        # Check for complex structures
        if isinstance(stmt, (ast.For, ast.While, ast.If, ast.Try, ast.With)):
            return False  # Has complex control flow
    # Consider trivial if no actual code lines (only docstring)
    return code_lines < 1


def _is_tiny_nested_function(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """
    Check if a nested function is too small to be a separate block.

    A nested function is considered tiny if it has less than 1 line of code.
    Args:
        node: AST FunctionDef or AsyncFunctionDef node.
        Returns:
        True if the nested function is tiny, False otherwise.
    """
    # Count total lines in body
    total_lines = 0
    for stmt in node.body:
        # Skip docstring if it's the first statement
        if total_lines == 0 and isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
            if isinstance(stmt.value.value, str):
                continue
        total_lines += 1
    # Consider tiny if empty (no actual code, only docstring)
    return total_lines < 1


def _class_symbol_type(parent_symbols: List[str]) -> str:
    """Return the catalog symbol type for a class node."""

    if parent_symbols:
        return "nested_class"
    return "class"


def _function_symbol_type(parent_symbols: List[str], parent_kind: str | None) -> str:
    """Return the catalog symbol type for a function-like node."""

    if parent_kind == "class":
        return "method"
    if parent_symbols:
        return "nested_function"
    return "function"


def _should_discover_function(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    parent_kind: str | None,
    module: str,
) -> bool:
    """
    Return whether a function-like node should become a block.
    Filters out:
    - All dunder methods in classes (__init__, __str__, etc.)
    - Trivial getters/setters (less than 3 lines of actual code)
    - Very small nested functions (less than 5 lines)
    """
    # Exclude all dunder methods in classes
    if parent_kind == "class" and node.name.startswith("__") and node.name.endswith("__"):
        return False
    # Exclude trivial getters/setters in classes (less than 3 lines of actual code)
    if parent_kind == "class" and _is_trivial_method(node):
        return False
    # Exclude very small nested functions (less than 5 lines)
    if parent_kind == "function" and _is_tiny_nested_function(node):
        return False
    return True


def _derive_module_path(relative_path: Path) -> str:
    """
    Derive module path from relative file path.

    Example:
        app/services/users.py -> app.services.users

    Args:
        relative_path: Relative path from project root.

    Returns:
        Module path as dotted string.
    """
    # Remove .py extension and convert to module path
    stem = relative_path.stem
    parent_parts = list(relative_path.parent.parts)
    if parent_parts:
        module = ".".join(parent_parts + [stem])
    else:
        module = stem
    return module


def _extract_imports(tree: ast.AST) -> List[str]:
    """
    Extract and normalize imports from AST.

    Args:
        tree: AST tree.

    Returns:
        List of normalized import strings.
    """
    imports: List[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                # Use the full module name, not the alias
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module if node.module else ""
            for alias in node.names:
                if alias.name == "*":
                    # Skip star imports for now
                    continue
                if module:
                    imports.append(f"{module}.{alias.name}")
                else:
                    # Relative import, use name as-is
                    imports.append(alias.name)

    return imports


def _extract_class_unit(
    node: ast.ClassDef,
    file_path: str,
    module: str,
    imports: List[str],
    symbol: str,
    symbol_type: str,
) -> Optional[DiscoveredCodeUnit]:
    """
    Extract class information from AST node.

    Args:
        node: AST ClassDef node.
        file_path: Relative file path.
        module: Module path.
        imports: List of imports from the module.

    Returns:
        DiscoveredCodeUnit or None.
    """
    methods = _extract_direct_child_function_qualified_names(
        nodes=node.body,
        module=module,
        parent_symbol=symbol,
        skip_dunder=True,
    )
    functions = _extract_direct_child_class_qualified_names(
        nodes=node.body,
        module=module,
        parent_symbol=symbol,
    )

    # Extract decorators
    decorators = _extract_decorators(node.decorator_list)

    # Extract docstring
    docstring = ast.get_docstring(node)

    # Extract structured calls from this class
    calls = _extract_structured_calls_from_node(node)

    return DiscoveredCodeUnit(
        path=file_path,
        module=module,
        symbol=symbol,
        symbol_type=symbol_type,
        qualified_name=f"{module}.{symbol}",
        start_line=node.lineno,
        end_line=node.end_lineno if hasattr(node, "end_lineno") else None,
        methods=methods,
        functions=functions,
        imports=imports,
        decorators=decorators,
        docstring=docstring,
        signature=None,        calls=calls,
    )


def _extract_function_unit(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    file_path: str,
    module: str,
    imports: List[str],
    symbol: str,
    symbol_type: str,
) -> Optional[DiscoveredCodeUnit]:
    """
    Extract function information from AST node.

    Args:
        node: AST FunctionDef or AsyncFunctionDef node.
        file_path: Relative file path.
        module: Module path.
        imports: List of imports from the module.

    Returns:
        DiscoveredCodeUnit or None.
    """
    # Extract decorators
    decorators = _extract_decorators(node.decorator_list)

    # Extract docstring
    docstring = ast.get_docstring(node)

    # Extract signature
    signature = _extract_function_signature(node)
    functions = _extract_direct_child_qualified_names(
        nodes=node.body,
        module=module,
        parent_symbol=symbol,
    )
    # Extract structured calls from this function
    calls = _extract_structured_calls_from_node(node)

    return DiscoveredCodeUnit(
        path=file_path,
        module=module,
        symbol=symbol,
        symbol_type=symbol_type,
        qualified_name=f"{module}.{symbol}",
        start_line=node.lineno,
        end_line=node.end_lineno if hasattr(node, "end_lineno") else None,
        methods=[],
        functions=functions,
        imports=imports,
        decorators=decorators,
        docstring=docstring,
        signature=signature,        calls=calls,
    )


def _extract_direct_child_symbols(nodes: List[ast.stmt], parent_symbol: str) -> List[str]:
    """Return direct nested block symbols for a code unit."""

    child_symbols: List[str] = []
    child_symbols.extend(
        _extract_direct_child_function_symbols(
            nodes=nodes,
            parent_symbol=parent_symbol,
            skip_dunder=False,
        )
    )
    child_symbols.extend(
        _extract_direct_child_class_symbols(
            nodes=nodes,
            parent_symbol=parent_symbol,
        )
    )
    return child_symbols


def _extract_direct_child_qualified_names(
    nodes: List[ast.stmt],
    module: str,
    parent_symbol: str,
) -> List[str]:
    """Return direct nested block qualified names for a code unit."""

    child_qualified: List[str] = []
    child_qualified.extend(
        _extract_direct_child_function_qualified_names(
            nodes=nodes,
            module=module,
            parent_symbol=parent_symbol,
            skip_dunder=False,
        )
    )
    child_qualified.extend(
        _extract_direct_child_class_qualified_names(
            nodes=nodes,
            module=module,
            parent_symbol=parent_symbol,
        )
    )
    return child_qualified


def _extract_direct_child_function_qualified_names(
    nodes: List[ast.stmt],
    module: str,
    parent_symbol: str,
    skip_dunder: bool,
) -> List[str]:
    """Return direct nested function-like qualified names for a code unit."""

    child_qualified: List[str] = []
    for node in nodes:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name.startswith("_") and not (
            node.name.startswith("__") and node.name.endswith("__")
        ):
            continue
        if skip_dunder and node.name.startswith("__") and node.name.endswith("__"):
            continue
        child_symbol = f"{parent_symbol}.{node.name}"
        child_qualified.append(f"{module}.{child_symbol}")
    return child_qualified


def _extract_direct_child_class_qualified_names(
    nodes: List[ast.stmt],
    module: str,
    parent_symbol: str,
) -> List[str]:
    """Return direct nested class qualified names for a code unit."""

    child_qualified: List[str] = []
    for node in nodes:
        if isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
            child_symbol = f"{parent_symbol}.{node.name}"
            child_qualified.append(f"{module}.{child_symbol}")
    return child_qualified


def _extract_direct_child_function_symbols(
    nodes: List[ast.stmt],
    parent_symbol: str,
    skip_dunder: bool,
) -> List[str]:
    """Return direct nested function-like symbols for a code unit."""

    child_symbols: List[str] = []
    for node in nodes:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name.startswith("_") and not (
            node.name.startswith("__") and node.name.endswith("__")
        ):
            continue
        if skip_dunder and node.name.startswith("__") and node.name.endswith("__"):
            continue
        child_symbols.append(f"{parent_symbol}.{node.name}")
    return child_symbols


def _extract_direct_child_class_symbols(
    nodes: List[ast.stmt],
    parent_symbol: str,
) -> List[str]:
    """Return direct nested class symbols for a code unit."""

    child_symbols: List[str] = []
    for node in nodes:
        if isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
            child_symbols.append(f"{parent_symbol}.{node.name}")
    return child_symbols


def _extract_decorators(decorator_list: List[ast.expr]) -> List[str]:
    """
    Extract decorator names from decorator list.

    Args:
        decorator_list: List of decorator AST nodes.

    Returns:
        List of decorator names.
    """
    decorators: List[str] = []

    for decorator in decorator_list:
        if isinstance(decorator, ast.Name):
            decorators.append(decorator.id)
        elif isinstance(decorator, ast.Attribute):
            # Handle @app.route style decorators
            decorators.append(_get_attribute_name(decorator))
        elif isinstance(decorator, ast.Call):
            # Handle @decorator(...) style
            if isinstance(decorator.func, ast.Name):
                decorators.append(decorator.func.id)
            elif isinstance(decorator.func, ast.Attribute):
                decorators.append(_get_attribute_name(decorator.func))
        else:
            # Try to unparse if available
            if hasattr(ast, "unparse"):
                try:
                    decorators.append(ast.unparse(decorator))
                except (AttributeError, ValueError, TypeError):
                    decorators.append("unknown")
            else:
                decorators.append("unknown")

    return decorators


def _get_attribute_name(node: ast.Attribute) -> str:
    """
    Get dotted name from attribute node.

    Args:
        node: AST Attribute node.

    Returns:
        Dotted name string.
    """
    parts = []
    current = node

    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value

    if isinstance(current, ast.Name):
        parts.append(current.id)

    return ".".join(reversed(parts))


def _extract_structured_calls_from_node(
    node: ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef,
) -> List[Dict[str, Any]]:
    """Extract structured call references from an AST node.
    
    Returns a list of dicts, each with 'context' and 'name' keys.
    
    Examples:
        - self.get_origin() → {"context": "self", "name": "get_origin"}
        - shard.get_blocks() → {"context": "shard", "name": "get_blocks"}
        - helper() → {"context": None, "name": "helper"}
        - Service() → {"context": None, "name": "Service"}
        - self.index.get_authority_config() → {"context": None, "name": "get_authority_config"} (chained, not resolved)
    
    Args:
        node: AST ClassDef, FunctionDef, or AsyncFunctionDef node.
        
    Returns:
        List of structured call dicts.
    """
    calls: List[Dict[str, Any]] = []
    
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        
        call_info = _analyze_call(child.func)
        if call_info:
            calls.append(call_info)
    
    # Remove duplicates while preserving order
    unique_calls: List[Dict[str, Any]] = []
    seen = set()
    for call in calls:
        key = (call.get("context"), call.get("name"))
        if key not in seen:
            seen.add(key)
            unique_calls.append(call)
    
    return unique_calls


def _analyze_call(func_node: ast.expr) -> Dict[str, Any] | None:
    """Analyze a call function node to extract context and name.
    
    Args:
        func_node: The AST expression representing the function being called.
        
    Returns:
        Dict with 'context' and 'name' keys, or None if not a local call.
    """
    # Case 1: self.method_name() or cls.method_name()
    if isinstance(func_node, ast.Attribute):
        # Check if the object being accessed is 'self' or 'cls'
        if isinstance(func_node.value, ast.Name):
            if func_node.value.id in ("self", "cls"):
                return {"context": func_node.value.id, "name": func_node.attr}
        # Otherwise it's shard.get_blocks(), self.index.get_config(), etc.
        # These require runtime type info, so we only capture the tail name
        # but context will indicate it's not self/cls
        return {"context": _extract_context_prefix(func_node.value), "name": func_node.attr}
    
    # Case 2: bare_name() - could be function or class constructor
    if isinstance(func_node, ast.Name):
        return {"context": None, "name": func_node.id}
    
    # Case 3: Other complex expressions - ignore for dependency resolution
    return None


def _extract_context_prefix(node: ast.expr) -> str | None:
    """Extract context prefix from an attribute chain.
    
    Examples:
        - self.index.get_config → "self.index"
        - shard.get_blocks → "shard"
        - obj.prop.method → "obj.prop"
    
    Args:
        node: AST expression node.
        
    Returns:
        Context prefix as string, or None.
    """
    if isinstance(node, ast.Name):
        return node.id
    
    if isinstance(node, ast.Attribute):
        parts = [node.attr]
        current = node.value
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    
    return None


def _extract_function_signature(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> Optional[str]:
    """
    Extract function signature as string.

    Args:
        node: AST FunctionDef or AsyncFunctionDef node.

    Returns:
        Signature string or None.
    """
    try:
        # Build signature manually for simplicity
        name = node.name
        args_part = _extract_args_string(node)
        return_annotation = _extract_return_annotation(node)

        if return_annotation:
            return f"{name}({args_part}) -> {return_annotation}"
        else:
            return f"{name}({args_part})"
    except (AttributeError, ValueError, TypeError):
        # If we can't safely render, try ast.unparse if available
        if hasattr(ast, "unparse"):
            try:
                return ast.unparse(node)
            except (AttributeError, ValueError, TypeError):
                pass
        return None


def _extract_args_string(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    """
    Extract function arguments as string.

    Args:
        node: AST FunctionDef or AsyncFunctionDef node.

    Returns:
        Arguments string.
    """
    args = []
    pos_only = []
    pos_or_kw = []
    kw_only = []
    vararg = None
    kwarg = None

    # Process positional-only arguments
    for arg in node.args.posonlyargs:
        pos_only.append(arg.arg)

    # Process positional or keyword arguments
    for arg in node.args.args:
        pos_or_kw.append(arg.arg)

    # Process keyword-only arguments
    for arg in node.args.kwonlyargs:
        kw_only.append(arg.arg)

    # Process *args
    if node.args.vararg:
        vararg = node.args.vararg.arg

    # Process **kwargs
    if node.args.kwarg:
        kwarg = node.args.kwarg.arg

    # Build the arguments list
    args.extend(pos_only)
    args.extend(pos_or_kw)
    if vararg:
        args.append(f"*{vararg}")
    args.extend(kw_only)
    if kwarg:
        args.append(f"**{kwarg}")

    return ", ".join(args)


def _extract_return_annotation(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> Optional[str]:
    """
    Extract return annotation from function node.

    Args:
        node: AST FunctionDef or AsyncFunctionDef node.

    Returns:
        Return annotation string or None.
    """
    if node.returns is None:
        return None

    try:
        if hasattr(ast, "unparse"):
            return ast.unparse(node.returns)
        else:
            # Fallback: simple representation
            return str(node.returns)
    except (AttributeError, ValueError, TypeError):
        return None


def _extract_parameter_annotation(arg: ast.arg) -> Optional[str]:
    """
    Extract type annotation from a parameter as string.

    Args:
        arg: AST arg node.

    Returns:
        Type annotation string or None.
    """
    if arg.annotation is None:
        return None

    try:
        if hasattr(ast, "unparse"):
            return ast.unparse(arg.annotation)
        else:
            return str(arg.annotation)
    except (AttributeError, ValueError, TypeError):
        return None


def _get_default_value(node: ast.FunctionDef | ast.AsyncFunctionDef, arg_name: str) -> Any:
    """
    Get the default value for a parameter as a Python literal.

    Args:
        node: AST FunctionDef or AsyncFunctionDef node.
        arg_name: Parameter name to find.

    Returns:
        Default value (can be any Python literal), or None if no default.
    """
    # Get defaults from args
    # args.args are positional or keyword arguments
    # defaults list aligns with the rightmost args
    defaults = node.args.defaults
    kw_defaults = node.args.kw_defaults
    posonlyargs = node.args.posonlyargs
    args_list = node.args.args
    kwonlyargs = node.args.kwonlyargs

    # Find which argument list contains our parameter
    default_index = None

    # Check positional-only args
    for i, arg in enumerate(posonlyargs):
        if arg.arg == arg_name:
            # Positional-only defaults are in the defaults list
            # They're aligned with the rightmost positional args
            num_posonly = len(posonlyargs)
            num_posorkw = len(args_list)
            total_positional = num_posonly + num_posorkw
            if len(defaults) > num_posorkw:
                # Defaults apply to positional-only as well
                idx = i - (total_positional - len(defaults))
                if 0 <= idx < len(defaults):
                    default_node = defaults[idx]
                    return _ast_to_literal(default_node) if default_node is not None else None
            return None

    # Check positional or keyword args
    for i, arg in enumerate(args_list):
        if arg.arg == arg_name:
            # Default index is relative to defaults list
            # defaults align with rightmost args
            num_args = len(args_list)
            if i >= num_args - len(defaults):
                default_index = i - (num_args - len(defaults))
                if 0 <= default_index < len(defaults):
                    default_node = defaults[default_index]
                    return _ast_to_literal(default_node) if default_node is not None else None
            return None

    # Check keyword-only args
    for i, arg in enumerate(kwonlyargs):
        if arg.arg == arg_name:
            if i < len(kw_defaults) and kw_defaults[i] is not None:
                default_node = kw_defaults[i]
                return _ast_to_literal(default_node) if default_node is not None else None
            return None

    # Check *args and **kwargs - they have no defaults
    return None


def _ast_to_literal(node: ast.AST) -> Any:
    """
    Convert an AST literal node to its Python value.

    Args:
        node: AST node representing a literal.

    Returns:
        Python value (None, bool, int, float, str) or the node string if not a simple literal.
    """
    if node is None:
        return None
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        # For simple names like None, True, False
        if node.id in ("None", "True", "False"):
            return {"None": None, "True": True, "False": False}[node.id]
    # For more complex expressions, return as string
    try:
        if hasattr(ast, "unparse"):
            return ast.unparse(node)
    except (AttributeError, ValueError, TypeError):
        pass
    return None

def _is_data_class(node: ast.ClassDef) -> bool:
    """Return True when a class has no non-constructor instance methods."""

    instance_methods = 0
    for statement in node.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if statement.name in ("__init__", "__init_subclass__"):
                continue
            has_static_decorator = any(
                isinstance(decorator, ast.Name) and decorator.id == "staticmethod"
                for decorator in statement.decorator_list
            )
            has_class_decorator = any(
                isinstance(decorator, ast.Name) and decorator.id == "classmethod"
                for decorator in statement.decorator_list
            )
            if not has_static_decorator and not has_class_decorator:
                instance_methods += 1
    return instance_methods == 0


def _is_protocol_or_abstract_class(node: ast.ClassDef) -> bool:
    """Return True when a class represents an abstract declaration."""

    for decorator in node.decorator_list:
        if isinstance(decorator, ast.Name) and decorator.id == "protocol":
            return True
        if isinstance(decorator, ast.Attribute) and decorator.attr == "Protocol":
            return True
    for base in node.bases:
        if isinstance(base, ast.Name) and base.id in {"ABC", "ABCMeta", "Protocol"}:
            return True
        if isinstance(base, ast.Attribute):
            attribute_name = _get_attribute_name(base)
            if any(name in attribute_name for name in ("ABC", "Protocol")):
                return True
    return False


def _is_decorator_nested_function(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    parent_kind: str | None,
    parent_symbols: List[str],
) -> bool:
    """
    Check if this is a nested function inside a decorator factory.
    Args:
        node: AST FunctionDef or AsyncFunctionDef node.
        parent_kind: Kind of parent node.
        parent_symbols: List of parent symbol names.
        Returns:
        True if it's a decorator nested function, False otherwise.
    """
    if parent_kind != "function":
        return False
    # Check if parent function name suggests it's a decorator factory
    if parent_symbols:
        parent_name = parent_symbols[-1]
        return "decorator" in parent_name.lower()
    return False

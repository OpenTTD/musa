# $Id$
#
# This file is part of musa.
# musa is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 2.
# musa is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details. You should have received a copy of the GNU General Public License along with musa. If not, see <http://www.gnu.org/licenses/>.
#

from compiler import parse
from compiler.ast import *

def literal_eval(node_or_string):
    """
    Safely evaluate an expression node or a string containing a Python
    expression.  The string or node provided may only consist of the
    following Python literal structures: strings, numbers, tuples,
    lists, dicts, booleans, and None.
    """
    _safe_names = {'None': None, 'True': True, 'False': False}
    if isinstance(node_or_string, basestring):
        node_or_string = parse(node_or_string, mode='eval')
    if isinstance(node_or_string, Expression):
        node_or_string = node_or_string.node
    def _convert(node):
        if isinstance(node, Const) and isinstance(node.value,
                (basestring, int, float, long, complex)):
             return node.value
        elif isinstance(node, Tuple):
             return tuple(map(_convert, node.nodes))
        elif isinstance(node, List):
             return list(map(_convert, node.nodes))
        elif isinstance(node, Dict):
             return dict((_convert(k), _convert(v)) for k, v
                      in node.items)
        elif isinstance(node, Name):
             if node.name in _safe_names:
                  return _safe_names[node.name]
        elif isinstance(node, UnarySub):
             return -_convert(node.expr)
        raise ValueError('malformed string')
    return _convert(node_or_string)

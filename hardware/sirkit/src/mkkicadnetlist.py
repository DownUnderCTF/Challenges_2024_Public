import pprint
import abc
import json

# https://gist.github.com/roberthoenig/30f08b64b6ba6186a2cdee19502040b4

CELL_TYPE_STATIC_NETS = {
    "ls86_xor": {7: "GND", 14: "VCC"},
    "ls00_nand": {7: "GND", 14: "VCC"},
    "ls40_nand": {7: "GND", 14: "VCC"},
    "ls42_decoder": {8: "GND", 16: "VCC"},
    "ls08_and": {7: "GND", 14: "VCC"},
    "ls02_nor": {7: "GND", 14: "VCC"},
    "ls04_inv": {7: "GND", 14: "VCC"},
}

CELL_TYPE_PINS = {
    "ls86_xor": [
        {"A": 1, "B": 2, "Y": 3},
        {"A": 4, "B": 5, "Y": 6},
        {"A": 10, "B": 9, "Y": 8},
        {"A": 13, "B": 12, "Y": 11},
    ],
    "ls00_nand": [
        {"A": 1, "B": 2, "Y": 3},
        {"A": 4, "B": 5, "Y": 6},
        {"A": 10, "B": 9, "Y": 8},
        {"A": 13, "B": 12, "Y": 11},
    ],
    "ls40_nand": [
        {"A": 1, "B": 2, "C": 4, "D": 5, "Y": 6},
        {"A": 13, "B": 12, "C": 10, "D": 9, "Y": 8},
    ],
    "ls42_decoder": [
        {"A": 15, "B": 14, "C": 13, "D": 12,
         "Y0": 1, "Y1": 2, "Y2": 3, "Y3": 4,
         "Y4": 5, "Y5": 6, "Y6": 7, "Y7": 9,
         "Y8": 10, "Y9": 11}
    ],
    "ls08_and": [
        {"A": 1, "B": 2, "Y": 3},
        {"A": 4, "B": 5, "Y": 6},
        {"A": 10, "B": 9, "Y": 8},
        {"A": 13, "B": 12, "Y": 11},
    ],
    "ls02_nor": [
        {"A": 3, "B": 2, "Y": 1},
        {"A": 6, "B": 5, "Y": 4},
        {"A": 8, "B": 9, "Y": 10},
        {"A": 11, "B": 12, "Y": 13},
    ],
    "ls04_inv": [
        {"A": 1, "Y": 2},
        {"A": 3, "Y": 4},
        {"A": 5, "Y": 6},
        {"A": 9, "Y": 8},
        {"A": 11, "Y": 10},
        {"A": 13, "Y": 12},
    ],
}

def normalize_str(string: str) -> list[str]:
    str_norm = []
    last_c = None
    is_str = False
    for c in string:
        if c == "\"":
            is_str = not is_str
            if is_str:
                # end of string, push!
                str_norm.append("")
        elif is_str:
            str_norm[-1] += c
        elif c.isalnum():
            if last_c.isalnum():
                str_norm[-1] += c
            else:
                str_norm.append(c)
        elif not c.isspace():
            str_norm.append(c)
        last_c = c
    return str_norm

def get_lisp_ast(input_norm: list[str]):
    ast = []
    # Go through each element in the input:
    # - if it is an open parenthesis, find matching parenthesis and make recursive
    #   call for content in-between. Add the result as an element to the current list.
    # - if it is an atom, just add it to the current list.
    i = 0
    while i < len(input_norm):
        symbol = input_norm[i]
        if symbol == '(':
            list_content = []
            match_ctr = 1 # If 0, parenthesis has been matched.
            while match_ctr != 0:
                i += 1
                if i >= len(input_norm):
                    raise ValueError("Invalid input: Unmatched open parenthesis.")
                symbol = input_norm[i]
                if symbol == '(':
                    match_ctr += 1
                elif symbol == ')':
                    match_ctr -= 1
                if match_ctr != 0:
                    list_content.append(symbol)             
            ast.append(get_lisp_ast(list_content))
        elif symbol == ')':
                raise ValueError("Invalid input: Unmatched close parenthesis.")
        else:
            try:
                ast.append(int(symbol))
            except ValueError:
                ast.append(symbol)
        i += 1
    return ast

def lisp_ast_to_dict(ast):
    values = {}
    key = ast[0]
    for pair in ast[1:]:
        if len(pair) == 1:
            values[pair[0]] = []
        elif isinstance(pair[1], list):
            k,v = lisp_ast_to_dict(pair)
            if k not in values:
                values[k] = []
            values[k].append(v)
        else:
            values[pair[0]] = pair[1]
    for k in values.keys():
        if isinstance(values[k], list) and len(values[k]) == 1:
            values[k] = values[k][0]

    return key, values



class LispSerializable(abc.ABC):
    @abc.abstractmethod
    def key(self) -> str | None:
        return ""
    
    def _serialize_pair(self, attr, val):
        if isinstance(val, str):
            return [f"({attr} \"{val}\")"]
        elif isinstance(val, list):
            items = [
                v.serialize()
                for v in val
            ]
            if attr.endswith("_"):
                return items
            else:
                items_str = " ".join(items)
                return [f"({attr} {items_str})"]
        else:
            raise ValueError(f"cant serialize: {attr} = {val}")

    def serialize(self):
        attrs = []
        for key in dir(self):
            if key.startswith("_"):
                continue
            if hasattr(getattr(self, key), '__call__'):
                continue

            attrs.extend(self._serialize_pair(key, getattr(self, key)))

        attrs_str = " ".join(attrs)
        return f"({self.key()} {attrs_str})"


class KicadComponentLibrarySource(LispSerializable): 
    lib: str
    part: str
    description: str

    def key(self):
        return "libsource"
    
    def __init__(self, lib, part, description):
        self.lib = lib
        self.part = part
        self.description = description

class KicadComponent(LispSerializable):
    ref: str
    value: str
    footprint: str
    libsource_: list[KicadComponentLibrarySource]
    def key(self):
        return "comp"
    
    def __init__(self, ref, value, footprint, libsources):
        self.ref = ref
        self.value = value
        self.footprint = footprint
        self.libsource_ = libsources
        

class KicadLibraryPartPin(LispSerializable):
    num: str
    name: str
    type: str

    def key(self):
        return "pin"
    
    def __init__(self, num, name, type):
        self.num = num
        self.name = name
        self.type = type

class KicadLibraryPart(LispSerializable):
    lib: str
    part: str
    pins: list[KicadLibraryPartPin]

    def key(self):
        return "libpart"
    
    def __init__(self, lib, part, pins):
        self.lib = lib
        self.part = part
        self.pins = pins

class KicadLibrary(LispSerializable):
    logical: str
    uri: str

    def key(self) -> str | None:
        return "library"

    def __init__(self, logical, uri):
        self.logical = logical
        self.uri = uri


class KicadNetNode(LispSerializable):
    ref: str
    pin: str
    
    def key(self) -> str | None:
        return "node"
    
    def __init__(self, ref, pin):
        self.ref = ref
        self.pin = str(pin)
        

class KicadNet(LispSerializable):
    code: str
    name: str
    node_: list[KicadNetNode]
    def key(self) -> str | None:
        return "net"
    

class KicadNetlist(LispSerializable):
    version: str
    design: list[None]
    components: list[KicadComponent]
    libraries: list[KicadLibrary]
    nets: list[KicadNet]

    def key(self):
        return "export"

    def __init__(self, components, libraries, nets):
        self.version = "E"
        self.design = []
        self.components = components
        self.libraries = libraries
        self.nets = nets


def yosys_to_component_list(module):
    # TODO: IO ports

    net_names = {}

    for name, net in module["netnames"].items():
        for i, bit_idx in enumerate(net["bits"]):
            net_names[bit_idx] = f"{name}.{i}"



    next_designator = 1
    unfull_chips = {}

    chips = []

    # group cells onto single IC
    for name, cell in module["cells"].items():
        cell_type = cell["type"]

        cells_per_ic = len(CELL_TYPE_PINS[cell_type])

        if cell_type not in unfull_chips:
            unfull_chips[cell_type] = []

        unfull_chips[cell_type].append(name)

        if len(unfull_chips[cell_type]) == cells_per_ic:
            chips.append(
                (f"U{next_designator:03}", cell_type, unfull_chips[cell_type])
            )
            next_designator += 1
            del unfull_chips[cell_type] 

    for cell_type, cells in unfull_chips.items():
        chips.append(
                (f"U{next_designator:03}", cell_type, cells)
            )
        next_designator += 1

    nets = {}  # name: (ref, pin)

    def add_net(name, ref, pin, use):
        if name not in nets:
            nets[name] = []
        nets[name].append((ref, pin, use))

    # assign chip pins to nets
    for chip in chips:
        ref, cell_type, cells = chip

        # apply static nets

        for pin, net in CELL_TYPE_STATIC_NETS[cell_type].items():
            add_net(net, ref, pin, net)


        for pin_assignments, cell in zip(CELL_TYPE_PINS[cell_type], cells):
            connections = module["cells"][cell]["connections"]

            for conn_name, target_pin in pin_assignments.items():
                assert len(connections[conn_name]) == 1
                net = net_names[connections[conn_name][0]]
                add_net(net, ref, target_pin, conn_name)

        
    return [
        (c[0], c[1]) for c in chips
    ], nets
    


def make_kicad_nets(nets):
    code = 1

    o_nets = []

    for net_name, nodes in nets.items():
        net = KicadNet()

        net.code = str(code)
        code += 1

        net.name = net_name

        k_nodes = []

        for ref, pin, _use in nodes:
            k_nodes.append(
                KicadNetNode(ref, pin)
            )

        net.node_ = k_nodes

        o_nets.append(net)

    return o_nets

def make_kicad_components(parts):
    comps = list()
    for ref, p_type in parts:
        value = {
            "ls86_xor": "74LS86",
            "ls00_nand": "74LS00",
            "ls40_nand": "74LS40",
            "ls08_and": "74LS08",
            "ls02_nor": "74LS02",
            "ls04_inv": "74LS04",
        }[p_type]

        footprint = "Package_DIP:DIP-14_W7.62mm"

        comp = KicadComponent(
            ref, value, footprint, 
            [KicadComponentLibrarySource(
                "74xx", value, "description!"
            )]
        )

        comps.append(comp)

    return comps
    

with open("sirkit.json") as f:
    j = json.load(f)
    y_parts, y_nets = yosys_to_component_list(j["modules"]["main"])

    
    k_nets = make_kicad_nets(y_nets)
    k_parts = make_kicad_components(y_parts)
    k_libraries = [
        KicadLibrary(
            "74xx",
            "/nix/store/ir8mpjdqa4n9h0fnlwwqbb356bwk50nx-kicad-symbols-099ac0c8ac/share/kicad/symbols/74xx.kicad_sym"
        )
    ]

    k_netlist = KicadNetlist(
        k_parts,
        k_libraries,
        k_nets
    )

    print(k_netlist.serialize())


# with open("sch/sch.net") as f:
#     n = normalize_str(f.read())
#     ast = get_lisp_ast(n)

#     k, d = lisp_ast_to_dict(ast[0])

#     pprint.pp(d)

# z3
import z3
import z3.z3printer

# log
from rich.logging import RichHandler
from rich.progress import Progress
import logging

import ghidra_bridge

FORMAT = "%( message )s"
logging.basicConfig(level="DEBUG", datefmt="[%X]", handlers=[RichHandler(markup=True)])
log = logging.getLogger("dz")

# Creates the bridge and loads the flat API into the global namespace
b = ghidra_bridge.GhidraBridge(namespace=globals())

pcode = b.remote_import("ghidra.program.model.pcode")
decompiler = b.remote_import("ghidra.app.decompiler")
symbol = b.remote_import("ghidra.program.model.symbol")
block = b.remote_import("ghidra.program.model.block")
data = b.remote_import("ghidra.program.model.data")
address = b.remote_import("ghidra.program.model.address")
listing = currentProgram.getListing()


def setupDecompile(currentProgram):

    decompInterface = decompiler.DecompInterface()

    options = decompiler.DecompileOptions()

    decompInterface.setOptions(options)

    decompInterface.toggleCCode(True)
    decompInterface.toggleSyntaxTree(True)
    decompInterface.setSimplificationStyle("decompile")

    return decompInterface


target_operation = [
    pcode.PcodeOp.INT_DIV,
    pcode.PcodeOp.INT_SDIV,
    pcode.PcodeOp.FLOAT_DIV,
]


def decompile(func):

    res = decomplib.decompileFunction(func, 60, monitor)
    high = res.getHighFunction()
    return high


def handle_constant(input, s: z3.Solver, x):
    log.info("handle constant: %s", input)

    y = z3.BitVec(input.toString(), input.getSize() * 8)
    s.add(x == y, y == input.getOffset())
    status = s.check()
    if status == z3.sat:
        log.debug("path: \n %s", s)
        result = s.model().eval(x)

        return result
    else:
        log.error("Not sat, may be a bug: %s", s)
    # y = z3.Real(input.toString())
    # s.add(x == y, y == input.getOffset())
    # status = s.check()
    # if status == z3.sat:
    #     log.debug("path: \n %s", s)
    #     result = s.model().eval(x)

    #     return result
    # else:
    #     log.error("Not sat, may be a bug: %s", s)


def handle_address(input, s: z3.Solver, x):
    log.info("handle address: %s", input)

    out = getReferencesTo(input.getAddress())
    for element in out:
        if element.getReferenceType() == symbol.DataRefType.WRITE:
            if element.isOperandReference():

                f1 = getFunctionContaining(element.getFromAddress())

                log.warning("current function: %s", f1)
                instruct = getInstructionContaining(element.getFromAddress())
                # op1 = instruct.getPcode()[element.getOperandIndex()]

                res = decomplib.decompileFunction(f1, 60, monitor)
                high = res.getHighFunction()
                ops = high.getPcodeOps(instruct.getAddress())
                for i in ops:
                    result = tracing(i.getInput(0), s, x)
                    return result
    log.debug("No write, may ba a pre-defined global variable")

    # TODO: Found a way to get the data of a global variable.
    if getSymbolAt(input.getAddress()).getName() == "_staticFalse":
        s.add(x == 0)
        return 0
    if getSymbolAt(input.getAddress()).getName() == "_staticTrue":
        s.add(x == 1)
        return 1


def handle_register(input, s: z3.Solver, x):
    log.info("handle register: %s", input)
    global last_function

    log.debug("It is may inside a function")

    out = getReferencesTo(last_function.getEntryPoint())
    value = 0

    for element in out:
        if element.getReferenceType() == symbol.DataRefType.EXTERNAL_REF:
            log.debug("element %s is a external call", element)
            continue
        f1 = getFunctionContaining(element.getFromAddress())
        if f1 != None:
            log.debug("Paraents function: %s", f1.getName())
            res = decomplib.decompileFunction(f1, 60, monitor)
            high = res.getHighFunction()
            opiter = high.getPcodeOps()
            while opiter.hasNext():
                op = opiter.next()
                if op.getOpcode() == pcode.PcodeOp.CALL:
                    log.debug("Found a call: %s", op)
                    if op.getNumInputs() > 1:
                        for i in range(1, op.getNumInputs()):
                            if (
                                op.getInput(0).getAddress()
                                != last_function.getEntryPoint()
                            ):
                                continue
                            else:
                                last_function = f1
                                log.debug("Tracing %s", op.getInput(i))
                                value = tracing(op.getInput(i), s, x)
        else:
            log.warning("Function is not called by any other functions")

        return value


block_model = block.BasicBlockModel(currentProgram)


def handle_cbranch(input, dest_block):
    log.info("handle cbranch: %s", input)
    s1 = z3.Solver()
    x = z3.BitVec(input.toString(), input.getSize() * 8)

    result = tracing(input, s1, x)
    log.debug("Branch condition is: %s", result)
    s1.reset()

    if result == None:
        log.debug("The result is None, skip branch for now.")

        return False
    else:
        return result


# TODO: need more attentation.
def handle_multiequal(last_operation, s: z3.Solver, x):
    log.info("handle MULTIEQUAL: %s", last_operation)

    global traced_varnode
    value = None

    log.debug("Checking if need branch analysis...")

    # check if a input comes from a branch.
    last_block = None
    for input in last_operation.getInputs():
        log.debug("Checking %s", input)

        defination_of_input = input.getDef()
        if defination_of_input != None:
            block = defination_of_input.getParent()
            if block.getInSize() == 1:

                stop_op = None
                # print(op.getParent().getIn(0))
                iter = block.getIn(0).getIterator()
                for op1 in iter:
                    stop_op = op1
                    # print(stop_op)
                if stop_op.getOpcode() == pcode.PcodeOp.CBRANCH:
                    log.debug("Found a cbranch")

                    traced_varnode = input
                    result = check_condition(stop_op.getInput(1))
                    if result == True:
                        log.debug(
                            "condition is true, start branch analysis, this input is valid"
                        )
                        if last_block != None:
                            if last_block != block:
                                if block.calcDepth(last_block) < 0:
                                    log.debug("depth < 0, it is a succcesser block")
                                    # print("depth: ", block.calcDepth(last_block))
                                    s.push()
                                    result = tracing(input, s, x)
                                    if result != None:
                                        log.info(
                                            "%s has a value %s, previous value will be replaced",
                                            input,
                                            result,
                                        )
                                        value = result

                                    s.pop()
                                else:
                                    log.warning("depth > 0, ignore this input")
                        else:
                            log.info("last_block is None, %s is the first input")
                            s.push()
                            result = tracing(input, s, x)
                            if result != None:
                                value = result
                            s.pop()
                            last_block = block

                    else:
                        log.info("condition is True, no need for branch analysis")
                        s.push()
                        result = tracing(input, s, x)
                        if result != None:
                            value = result
                        s.pop()
                        last_block = block
                else:
                    log.info("input not from cbranch, do the normal analysis")
                    s.push()
                    result = tracing(input, s, x)
                    if result != None:
                        value = result
                    s.pop()
                    last_block = block

            else:
                log.info(
                    "block has multiple or zero in blocks, it could be a entry block"
                )
                s.push()
                result = tracing(input, s, x)
                if result != None:
                    value = result
                s.pop()
            last_block = block
        else:
            log.warning("last operation is None")

    log.debug("Output of multiequal %s is %s", last_operation.getOutput(), value)

    s.add(x == value)

    return value


cast_function = ["_atof", "_atoi"]


def handle_call(last_operation, s: z3.Solver, x):
    log.info("handle function call: %s", last_operation)

    global last_function
    # print("Found CALL: ", s)
    f = getFunctionAt(last_operation.getInput(0).getAddress())
    log.debug("The function is %s", f)

    if f.getName() in cast_function:
        log.debug("Data cast occured: %s", f.getName())
        if last_operation.getInput(1).isConstant():
            return handle_constant(last_operation.getInput(1), s, x)
        if last_operation.getInput(1).isUnique():
            return handle_unique(last_operation.getInput(1), s, x)
        else:
            log.error("Not covered yet")

    if f.getName() == "_socket":
        log.debug(
            "call builtin function %s which return value can't be decided", f.getName()
        )
        return False
    if f.getName() == "_recv":
        log.debug(
            "call builtin function %s which return value can't be decided", f.getName()
        )
        return False
    if f.getName() == "_connect":
        log.debug(
            "call builtin function %s which return value can't be decided", f.getName()
        )
        return True

    else:
        high = decompile(f)
        opiter = high.getPcodeOps()
        while opiter.hasNext():
            op = opiter.next()
            if op.getOpcode() == pcode.PcodeOp.RETURN:
                log.debug("Found RETURN: %s", op)
                if op.getNumInputs() > 1:
                    if op.getInput(1).isConstant():
                        return handle_constant(op.getInput(1), s, x)

                    # TODO: hadnle address
                    elif op.getInput(1).isAddress():
                        log.warning("Found a address, do nothing for now.")
                        return handle_address(op.getInput(1), s, x)
                    elif op.getInput(1).isRegister():
                        log.warning("It is parameter: %s", op.getInput(1))
                        last_function = f
                        return tracing(op.getInput(1), s, x)
                else:
                    log.error("not covered yet")


def handle_indirect(last_operation, s: z3.Solver, x):
    log.info("handle indirect: %s", last_operation)
    # Check the right value is a constant
    if last_operation.getInput(0).isConstant():
        return handle_constant(last_operation.getInput(0), s, x)
    else:
        y = z3.BitVec(
            last_operation.getInput(0).toString(),
            last_operation.getInput(0).getSize() * 8,
        )
        s.add(x == y)
        return tracing(last_operation.getInput(0), s, y)


def handle_copy(last_operation, s: z3.Solver, x):
    log.info("handle copy: %s", last_operation)

    # Check the right value is a constant
    if last_operation.getInput(0).isConstant():
        return handle_constant(last_operation.getInput(0), s, x)
    else:
        y = z3.BitVec(
            last_operation.getInput(0).toString(),
            last_operation.getInput(0).getSize() * 8,
        )
        s.add(x == y)
        return tracing(last_operation.getInput(0), s, y)


def handle_notequal(last_operation, s, x):
    log.info("handle notequal: %s", last_operation)
    y = z3.BitVec(
        last_operation.getInput(0).toString(), last_operation.getInput(0).getSize() * 8
    )
    z = z3.BitVec(
        last_operation.getInput(1).toString(), last_operation.getInput(1).getSize() * 8
    )

    s.add(y != z, z == last_operation.getInput(1).getOffset())

    tracing(last_operation.getInput(0), s, y)

    status = s.check()
    if status == z3.sat:
        log.debug("path: \n %s", s)
        result = s.model().eval(y != z)
        # print(result)
        return result
    else:
        log.error("Not sat, may be a bug: %s", s)


def handle_equal(last_operation, s, x):

    log.info("handle equal: %s", last_operation)
    y = z3.BitVec(
        last_operation.getInput(0).toString(), last_operation.getInput(0).getSize() * 8
    )
    z = z3.BitVec(
        last_operation.getInput(1).toString(), last_operation.getInput(1).getSize() * 8
    )

    s.add(y == z, z == last_operation.getInput(1).getOffset())

    tracing(last_operation.getInput(0), s, y)

    status = s.check()
    if status == z3.sat:
        log.debug("path: \n %s", s)
        result = s.model().eval(y == z)
        return result
    else:
        log.error("Not sat, may be a bug: %s", s)


def handle_sless(last_operation, s: z3.Solver):
    log.info("handle sless: %s", last_operation)

    s1 = z3.Solver()
    y = z3.BitVec(
        last_operation.getInput(0).toString(), last_operation.getInput(0).getSize() * 8
    )

    y_value = tracing(last_operation.getInput(0), s1, y)
    # print(y_value, last_operation.getInput(1).getOffset())
    if y_value <= last_operation.getInput(1).getOffset():
        log.debug("it is true")
        return True
    else:
        log.debug("it is false")
        return False


def handle_unique(input, s, x):

    log.info("handle unique: %s", input)

    y = z3.BitVec(input.toString(), input.getSize() * 8)
    s.add(x == y)
    # print(s)

    return tracing(input, s, y)


def handle_ptrsub(last_operation, s, x):
    log.info("handle ptrsub: %s", last_operation)

    # https://github.com/NationalSecurityAgency/ghidra/issues/2823
    y = z3.BitVec(
        last_operation.getInput(0).toString(), last_operation.getInput(0).getSize() * 8
    )
    s.add(x == y)
    if last_operation.getInput(0).isConstant():
        # it is a constant, just use it and get the address.
        log.debug("%s is a constant", last_operation.getInput(0))

    else:
        # Found it on https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/ghidra_scripts/ShowConstantUse.java
        # not a constant, so we had to track it.
        log.debug(
            "%s access data structure, so value can't be determined for now.",
            last_operation.getInput(0),
        )
        log.debug("path: \n %s", s)
        return None


def handle_load(last_operation, s, x):
    log.info("handle load: %s", last_operation)

    # Found store in current function
    # The most simple case, there is only one STORE in function
    # TODO: Make it more generic
    high_func = decompile(func)
    ops = high_func.getPcodeOps()
    for op in ops:
        if op.getOpcode() == pcode.PcodeOp.STORE:
            log.debug("Found the store in current function")
            return tracing(op.getInput(2), s, x)

    # Assume the denominator is function's parameter, found cross reference of this function, then trace it
    # TODO: very limited, should cover more edge cases.
    refs = getReferencesTo(func.getEntryPoint())
    for ref in refs:
        if ref.getReferenceType() == symbol.RefType.UNCONDITIONAL_CALL:
            fff = getFunctionContaining(ref.getFromAddress())
            fffhigh = decompile(fff)
            log.debug("Tracing in %s", fff)
            ops = fffhigh.getPcodeOps()
            for op in ops:
                if op.getOpcode() == pcode.PcodeOp.STORE:
                    log.info("Found a store in Paraents function")
                    log.debug("op: %s", op)

                    return tracing(op.getInput(2), s, x)

            log.debug("Not found a store, use found the indirect instead")
            ops = fffhigh.getPcodeOps()
            for op in ops:
                # print(op.getSeqnum(), op)
                if op.getOpcode() == pcode.PcodeOp.INDIRECT:
                    seqnum = pcode.SequenceNumber(
                        op.getInput(0).getPCAddress(), op.getInput(1).getOffset()
                    )
                    op1 = fffhigh.getPcodeOps(seqnum.getTarget())
                    for opppp in op1:
                        if opppp.getOpcode() == pcode.PcodeOp.COPY:
                            return handle_copy(opppp, s, x)


def handle_intand(last_operation, s, x):
    log.info("handle intadd: %s", last_operation)

    # First input is a constant, tracing another input
    if last_operation.getInput(0).isConstant():
        ss = z3.Solver()
        y = z3.BitVec(
            last_operation.getInput(1).toString(),
            last_operation.getInput(1).getSize() * 8,
        )
        input1 = tracing(last_operation.getInput(1), ss, y)
        if input1 != None:
            input0 = z3.BitVec(
                last_operation.getInput(0).toString(),
                last_operation.getInput(0).getSize() * 8,
            )
            z = z3.BitVec("z", last_operation.getInput(0).getSize() * 8)

            s.add(input0 == last_operation.getInput(0).getOffset())
            zero = z3.BitVecVal(0, 32)
            input1 = z3.Concat(zero, input1)
            s.add(z == input0 & input1)
            s.add(z == x)

            pass
    elif last_operation.getInput(1).isConstant():
        ss = z3.Solver()
        y = z3.BitVec(
            last_operation.getInput(0).toString(),
            last_operation.getInput(0).getSize() * 8,
        )
        input0 = tracing(last_operation.getInput(0), ss, y)
        if input0 != None:
            input1 = z3.BitVec(
                last_operation.getInput(1).toString(),
                last_operation.getInput(1).getSize() * 8,
            )
            z = z3.BitVec("z", last_operation.getInput(1).getSize() * 8)

            s.add(input1 == last_operation.getInput(1).getOffset())
            zero = z3.BitVecVal(0, 32)
            input0 = z3.Concat(zero, input0)
            s.add(z == input0 & input1)
            s.add(z == x)

    else:
        pass


def handle_float2float(last_operation, s, x):
    s1 = z3.Solver()
    y = z3.BitVec(
        last_operation.getInput(0).toString(), last_operation.getInput(0).getSize() * 8
    )
    result = tracing(last_operation.getInput(0), s1, y)
    return result


#     y = z3.BitVec(
#         last_operation.getInput(0).toString(), last_operation.getInput(0).getSize() * 8
#     )
#     s.add(x == y)
#     print(s)
#


def handle_subpiece(last_operation, s, x):
    s1 = z3.Solver()
    y = z3.BitVec(
        last_operation.getInput(0).toString(), last_operation.getInput(0).getSize() * 8
    )
    result = tracing(last_operation.getInput(0), s1, y)
    if result == False:
        log.warning("Can't be traced")


def tracing(input, s: z3.Solver, x):

    global executed_seqnums

    last_operation = input.getDef()

    # The last operation is None when input is constant, address(global variable), register(function parameter)
    # in normal case, it is the end of a path.
    if last_operation == None:
        log.debug("last operation is None")
        # check input is a constant, normally it is not.
        if input.isConstant():
            return handle_constant(input, s, x)
        if input.isAddress():
            return handle_address(input, s, x)
        if input.isRegister():
            return handle_register(input, s, x)
        if input.isUnique():
            return handle_unique(input, s, x)
        log.warning("No matched handler.")
    else:
        log.debug("last operation: %s %s", last_operation.getSeqnum(), last_operation)
        # Last operation is not None.
        # 1. Check the statements is a assignment.
        if last_operation.getSeqnum() in executed_seqnums:
            log.warning("Here we have a executed operation, skip... %s", last_operation)
            return
        else:
            executed_seqnums.append(last_operation.getSeqnum())

        if last_operation.isAssignment():

            # 2. It is a assignment, then check opcode, enter analysis functions.
            if last_operation.getOpcode() == pcode.PcodeOp.MULTIEQUAL:
                return handle_multiequal(last_operation, s, x)
            if last_operation.getOpcode() == pcode.PcodeOp.CALL:
                return handle_call(last_operation, s, x)
            if last_operation.getOpcode() == pcode.PcodeOp.INDIRECT:
                return handle_indirect(last_operation, s, x)
            if last_operation.getOpcode() == pcode.PcodeOp.COPY:
                return handle_copy(last_operation, s, x)
            if last_operation.getOpcode() == pcode.PcodeOp.INT_NOTEQUAL:
                return handle_notequal(last_operation, s, x)
            if last_operation.getOpcode() == pcode.PcodeOp.INT_EQUAL:
                return handle_equal(last_operation, s, x)
            if last_operation.getOpcode() == pcode.PcodeOp.INT_SLESS:
                return handle_sless(last_operation, s)
            if last_operation.getOpcode() == pcode.PcodeOp.PTRSUB:
                return handle_ptrsub(last_operation, s, x)
            if last_operation.getOpcode() == pcode.PcodeOp.LOAD:
                return handle_load(last_operation, s, x)
            if last_operation.getOpcode() == pcode.PcodeOp.INT_AND:
                return handle_intand(last_operation, s, x)
            if last_operation.getOpcode() == pcode.PcodeOp.FLOAT_FLOAT2FLOAT:
                return handle_float2float(last_operation, s, x)
            if last_operation.getOpcode() == pcode.PcodeOp.SUBPIECE:
                return handle_subpiece(last_operation, s, x)

            # Some operation does not handled for now.
            log.warning("not handled specially")
            y = z3.BitVec(
                last_operation.getInput(0).toString(),
                last_operation.getInput(0).getSize() * 8,
            )
            # when not matched, do this section
            s.add(x == y)
            return tracing(last_operation.getInput(0), s, y)

        else:
            # the last operation is not a assignment, usually this won't happen, but put it here just in case.
            log.error("It is not a assignment")


def handle_lessequal(last_operation, s, x):

    log.info("handle lessequal: %s", last_operation)
    y = z3.BitVec(
        last_operation.getInput(0).toString(), last_operation.getInput(0).getSize() * 8
    )
    z = z3.BitVec(
        last_operation.getInput(1).toString(), last_operation.getInput(1).getSize() * 8
    )

    s.add(y <= z, z == last_operation.getInput(1).getOffset())

    tracing(last_operation.getInput(0), s, y)

    status = s.check()
    if status == z3.sat:
        log.debug("path: \n %s", s)
        result = s.model().eval(y <= z)
        return result
    else:
        log.error("Not sat, may be a bug: %s", s)

    pass


def check_condition(stop_op_input):

    global traced_varnode
    log.info("check cbranch condition: %s", stop_op_input)
    if stop_op_input == traced_varnode:
        # TODO: should check the sink value?
        # print(traced_varnode)
        return True

    last_of_stop_op = stop_op_input.getDef()

    if last_of_stop_op != None:
        if last_of_stop_op.getOpcode() == pcode.PcodeOp.FLOAT_LESSEQUAL:
            s = z3.Solver()
            x = z3.BitVec(
                last_of_stop_op.getInput(0).toString(),
                last_of_stop_op.getInput(0).getSize() * 8,
            )
            return handle_lessequal(last_of_stop_op, s, x)

        elif last_of_stop_op.getOpcode() == pcode.PcodeOp.CAST:
            return check_condition(last_of_stop_op.getInput(0))

        elif last_of_stop_op.getOpcode() == pcode.PcodeOp.INT_AND:
            if last_of_stop_op.getInput(0).isConstant():
                log.debug("check input 0")
                log.debug("Not implementated yet")
                return check_condition(last_of_stop_op.getInput(1))
            if last_of_stop_op.getInput(1).isConstant():
                log.debug("check input 1")
                log.debug("Not implementated yet")
                return check_condition(last_of_stop_op.getInput(0))
        elif last_of_stop_op.getOpcode() == pcode.PcodeOp.INT_NOTEQUAL:
            s = z3.Solver()
            x = z3.BitVec(
                last_of_stop_op.getInput(0).toString(),
                last_of_stop_op.getInput(0).getSize() * 8,
            )
            return handle_notequal(last_of_stop_op, s, x)
        elif last_of_stop_op.getOpcode() == pcode.PcodeOp.INT_EQUAL:
            s = z3.Solver()
            x = z3.BitVec(
                last_of_stop_op.getInput(0).toString(),
                last_of_stop_op.getInput(0).getSize() * 8,
            )
            return handle_equal(last_of_stop_op, s, x)
        else:
            log.debug("not matched")
            return check_condition(last_of_stop_op.getInput(0))
    else:
        log.debug("last_of_stop_op is None, condition is False")
        return False


traced_varnode = None

bad_count = 0
b2g_count = 0
g2b_count = 0


def foundDiv(func):
    global executed_seqnums
    global traced_varnode

    global bad_count
    global b2g_count
    global g2b_count
    global bad_count_total
    global b2g_count_total
    global g2b_count_total

    counted_func = None
    high = decompile(func)
    opiter = high.getPcodeOps()
    while opiter.hasNext():
        op = opiter.next()

        if op.getOpcode() in target_operation:
            if "bad" in func.getName():
                print("total counted")
                if counted_func != func:
                    bad_count_total = bad_count_total + 1
                    counted_func = func
            if "G2B" in func.getName():
                g2b_count_total = g2b_count_total + 1
            if "B2G" in func.getName():
                b2g_count_total = b2g_count_total + 1

            print(bad_count_total, g2b_count_total, b2g_count_total)

            log.debug("Found a div operation: %s", op.toString())

            # if there is only one way in, do this
            if op.getParent().getInSize() == 1:

                stop_op = None
                # print(op.getParent().getIn(0))
                iter = op.getParent().getIn(0).getIterator()
                for op1 in iter:
                    stop_op = op1
                    # print(stop_op)
                if stop_op.getOpcode() == pcode.PcodeOp.CBRANCH:
                    log.debug("Found a cbranch")

                    traced_varnode = op.getInput(1)
                    # TODO: Use false out and true out
                    result = check_condition(stop_op.getInput(1))
                    executed_seqnums.clear()
                    if result == True:
                        log.info("safe")
                        if "B2G" in func.getName():
                            b2g_count = b2g_count + 1
                            print("B2G", b2g_count)
                            print("B2G", b2g_count, b2g_count_total)
                            print("B2G: ", b2g_count / b2g_count_total)
                            return
                    else:
                        log.info("unsafe, do the rest.")

            s = z3.Solver()

            # define the tracking variable as x
            x = z3.BitVec(op.getInput(1).toString(), op.getInput(1).getSize() * 8)

            # tracing the denominator
            result = tracing(op.getInput(1), s, x)
            log.info("denominator is : %s", result)

            if result == 0:
                if "bad" in func.getName():
                    print("bad counted")
                    bad_count = bad_count + 1
            elif result == None:
                pass
            else:
                if "G2B" in func.getName():
                    g2b_count = g2b_count + 1

            if "bad" in func.getName():
                print("bad", bad_count, bad_count_total)
                print("bad: ", bad_count / bad_count_total)
            if "G2B" in func.getName():
                print("G2B", g2b_count, g2b_count_total)
                print("G2B: ", g2b_count / g2b_count_total)

    executed_seqnums.clear()


executed_seqnums = []
last_function = None

bad_count_total = 0
g2b_count_total = 0
b2g_count_total = 0
current_function = None


if __name__ == "__main__":

    decomplib = setupDecompile(currentProgram)

    if not decomplib.openProgram(currentProgram):
        log.error("can't open current program")

    functions = currentProgram.getFunctionManager().getFunctions(True)

    with Progress(transient=True, auto_refresh=False) as progress:

        task = progress.add_task(
            "Going through functions",
            total=currentProgram.getFunctionManager().getFunctionCount(),
            completed=1,
        )

        for func in functions:
            last_function = func
            current_function = func

            log.warning("Current Function: %s", func)

            if func.getName() != "entry":
                foundDiv(func)

                # define last_function in case confilict with call.
                # func = getFunctionAfter(func)
                last_function = func
                progress.refresh()
                progress.advance(task)

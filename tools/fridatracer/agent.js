/**
 * Frida Agent: agent.js (Byte-Level Execution Observer with Taint Tracking)
 *
 * Hooks recv/recvfrom/recvmsg and uses Stalker with putCallout to:
 *   1. Detect which bytes of the recv buffer are read
 *   2. Track register taint — when a buffer byte is loaded into a register,
 *      that register is "tainted" with the buffer offset
 *   3. When cmp/test uses a tainted register, report the associated buffer
 *      offset as a branch-influencing offset
 *
 * Event types:
 *   recv_event    — recv returned, includes buffer_size
 *   buffer_access — memory-read instruction accessed a buffer byte (with offset)
 *   branch        — cmp/test/j* instruction; offset is non-null when it
 *                   references a tainted register or reads from the buffer
 *   instruction   — any other memory-read instruction (backward compat)
 */
'use strict';

const threadStates = new Map();

/* ── x86/x64 register normalization ── */
const REG_NORM = {};
(function buildRegMap() {
    const families = [
        [['al', 'ah', 'ax', 'eax', 'rax'], 'rax'],
        [['bl', 'bh', 'bx', 'ebx', 'rbx'], 'rbx'],
        [['cl', 'ch', 'cx', 'ecx', 'rcx'], 'rcx'],
        [['dl', 'dh', 'dx', 'edx', 'rdx'], 'rdx'],
        [['sil', 'si', 'esi', 'rsi'], 'rsi'],
        [['dil', 'di', 'edi', 'rdi'], 'rdi'],
        [['bpl', 'bp', 'ebp', 'rbp'], 'rbp'],
        [['spl', 'sp', 'esp', 'rsp'], 'rsp'],
    ];
    for (let i = 8; i <= 15; i++) {
        families.push([[`r${i}b`, `r${i}w`, `r${i}d`, `r${i}`], `r${i}`]);
    }
    for (const [aliases, canonical] of families) {
        for (const a of aliases) REG_NORM[a] = canonical;
    }
})();

function norm(reg) { return reg ? (REG_NORM[reg] || reg) : null; }

/* ── Branch-related mnemonics ── */
const CMP_TEST = new Set(['cmp', 'test']);
const BRANCH_MNEMONICS = new Set([
    'cmp', 'test',
    'ja', 'jae', 'jb', 'jbe', 'jc', 'je', 'jg', 'jge', 'jl', 'jle',
    'jna', 'jnae', 'jnb', 'jnbe', 'jnc', 'jne', 'jng', 'jnge', 'jnl',
    'jnle', 'jno', 'jnp', 'jns', 'jnz', 'jo', 'jp', 'jpe', 'jpo',
    'js', 'jz', 'jmp', 'jcxz', 'jecxz', 'jrcxz',
    'cmove', 'cmovne', 'cmovg', 'cmovge', 'cmovl', 'cmovle',
    'cmova', 'cmovae', 'cmovb', 'cmovbe',
]);

function isBranch(mn) { return BRANCH_MNEMONICS.has(mn); }
function isCmpTest(mn) { return CMP_TEST.has(mn); }
function isMemoryRead(i) { return i.operands.some(o => o.type === 'mem' && o.access.includes('r')); }

/* ── Helpers to extract operand info at transform (static) time ── */

function getMemReadOp(instruction) {
    for (const op of instruction.operands)
        if (op.type === 'mem' && op.access.includes('r')) return op.value;
    return null;
}

function getWriteReg(instruction) {
    for (const op of instruction.operands)
        if (op.type === 'reg' && op.access.includes('w')) return norm(op.value);
    return null;
}

function getReadRegs(instruction) {
    const regs = [];
    for (const op of instruction.operands)
        if (op.type === 'reg' && op.access.includes('r')) regs.push(norm(op.value));
    return regs;
}

/* ── Effective address computation helper ── */

function computeEA(context, memOp) {
    const baseReg = memOp.base ? norm(memOp.base) : null;
    const indexReg = memOp.index ? norm(memOp.index) : null;
    const scale = memOp.scale || 1;
    const disp = memOp.disp || 0;

    let ea = ptr(disp);
    if (baseReg && context[baseReg]) ea = ea.add(context[baseReg]);
    if (indexReg && context[indexReg]) {
        let idx = context[indexReg];
        /* Multiply by scale via repeated addition (scale ∈ {1,2,4,8}) */
        for (let s = 1; s < scale; s++) idx = idx.add(context[indexReg]);
        ea = ea.add(idx);
    }
    return ea;
}

function isInBuffer(ea, state) {
    return ea.compare(state.buffer) >= 0 && ea.compare(state.buffer.add(state.size)) < 0;
}

/* ═══════════════════════════════════════════════════════════════════
   Callout factories (called at transform time, return runtime fns)
   ═══════════════════════════════════════════════════════════════════ */

/**
 * Memory-read instruction callout:
 *   - If reading from buffer → taint destReg, emit buffer_access
 *   - If NOT from buffer     → clear destReg taint, emit instruction
 */
function makeMemReadCallout(memOp, destReg, mnemonic, state) {
    return function (context) {
        try {
            const ea = computeEA(context, memOp);

            if (isInBuffer(ea, state)) {
                const offset = ea.sub(state.buffer).toInt32();
                if (destReg) state.taintMap[destReg] = offset;
                send({ type: 'instruction', payload: { type: 'buffer_access', mnemonic, offset } });
            } else {
                if (destReg) delete state.taintMap[destReg];
                send({ type: 'instruction', payload: { type: 'instruction', mnemonic } });
            }
        } catch (e) { }
    };
}

/**
 * cmp/test callout — checks both memory operand and tainted registers.
 * Reports the buffer offset that influences the comparison.
 */
function makeCmpTestCallout(memOp, readRegs, mnemonic, state) {
    return function (context) {
        try {
            let offset = null;

            /* 1. Direct memory read from buffer? */
            if (memOp) {
                const ea = computeEA(context, memOp);
                if (isInBuffer(ea, state)) {
                    offset = ea.sub(state.buffer).toInt32();
                }
            }

            /* 2. Tainted register operand? */
            if (offset === null) {
                for (const reg of readRegs) {
                    if (state.taintMap[reg] !== undefined) {
                        offset = state.taintMap[reg];
                        break;
                    }
                }
            }

            send({ type: 'instruction', payload: { type: 'branch', mnemonic, offset } });
        } catch (e) { }
    };
}


/* ═══════════════════════════════════════════════════════════════════
   Hook recv / recvfrom / recvmsg
   ═══════════════════════════════════════════════════════════════════ */

try {
    send({ type: 'log', payload: 'Agent script started.' });

    const recvPtr = DebugSymbol.fromName('recv').address;
    const recvfromPtr = DebugSymbol.fromName('recvfrom').address;
    const recvmsgPtr = DebugSymbol.fromName('recvmsg').address;

    const functionsToHook = {
        'recv': recvPtr,
        'recvfrom': recvfromPtr,
        'recvmsg': recvmsgPtr,
    };

    let hook_count = 0;
    for (const [funcName, funcPtr] of Object.entries(functionsToHook)) {
        if (funcPtr && !funcPtr.isNull()) {
            hook_count++;
            Interceptor.attach(funcPtr, {
                onEnter: function (args) {
                    const threadId = this.threadId;
                    if (threadStates.has(threadId)) {
                        Stalker.unfollow(threadId);
                        threadStates.delete(threadId);
                    }
                    let state = {
                        buffer: ptr(0),
                        size: 0,
                        msghdr_ptr: null,
                        taintMap: {}       /* register → buffer offset */
                    };
                    if (funcName === 'recvmsg') {
                        state.msghdr_ptr = args[1];
                    } else {
                        state.buffer = args[1];
                    }
                    threadStates.set(threadId, state);
                },

                onLeave: function (retval) {
                    const bytesRead = retval.toInt32();
                    const threadId = this.threadId;
                    const state = threadStates.get(threadId);

                    if (bytesRead <= 0 || !state) return;

                    /* Resolve buffer for recvmsg */
                    if (state.msghdr_ptr) {
                        for (let i = 0; i < 8; i++) {
                            try {
                                const iov_ptr = state.msghdr_ptr.add(i * 8).readPointer();
                                if (iov_ptr.toInt32() > 4096) {
                                    const buffer_len = iov_ptr.add(Process.pointerSize).readU64();
                                    if (buffer_len.toNumber() >= bytesRead) {
                                        state.buffer = iov_ptr.readPointer();
                                        break;
                                    }
                                }
                            } catch (e) { }
                        }
                    }

                    if (state.buffer.isNull()) return;

                    state.size = bytesRead;
                    state.taintMap = {};  /* reset taints for new recv */

                    send({
                        type: 'instruction',
                        payload: { type: 'recv_event', buffer_size: bytesRead }
                    });

                    Stalker.follow(threadId, {
                        transform: function (iterator) {
                            let instruction;
                            while ((instruction = iterator.next()) !== null) {
                                const mn = instruction.mnemonic;
                                const memRead = isMemoryRead(instruction);

                                if (isCmpTest(mn)) {
                                    /* cmp / test — check both memory and taint */
                                    const memOp = getMemReadOp(instruction);
                                    const readRegs = getReadRegs(instruction);
                                    iterator.putCallout(
                                        makeCmpTestCallout(memOp, readRegs, mn, state)
                                    );

                                } else if (memRead) {
                                    /* Non-branch memory read — check buffer, manage taint */
                                    const memOp = getMemReadOp(instruction);
                                    const destReg = getWriteReg(instruction);
                                    iterator.putCallout(
                                        makeMemReadCallout(memOp, destReg, mn, state)
                                    );

                                } else if (isBranch(mn)) {
                                    /* Conditional jump — log statically, no offset */
                                    send({
                                        type: 'instruction',
                                        payload: { type: 'branch', mnemonic: mn, offset: null }
                                    });

                                } else {
                                    /* Non-memory-write clears taint for overwritten regs */
                                    const wr = getWriteReg(instruction);
                                    if (wr) delete state.taintMap[wr];
                                }

                                iterator.keep();
                            }
                        }
                    });
                }
            });
        }
    }

    if (hook_count > 0) {
        send({ type: 'log', payload: `[SUCCESS] Attached to ${hook_count} recv* functions with taint tracking.` });
    } else {
        send({ type: 'error', payload: 'Could not find any recv* functions to hook.' });
    }

} catch (error) {
    send({ type: 'error', payload: `[FATAL] ${error.message}` });
}
/**
 * Frida Agent: agent.js (Byte-Level Execution Observer)
 *
 * Hooks recv/recvfrom/recvmsg and uses Stalker with putCallout to observe
 * which bytes of the received buffer are accessed at runtime and which
 * offsets influence control flow (cmp/test/j* instructions).
 *
 * Event types emitted:
 *   buffer_access — a memory-read instruction accessed a byte within the recv buffer
 *   branch        — a cmp/test/j* instruction; includes buffer offset if operand is in buffer
 *   instruction   — any other memory-read instruction (backward compatible)
 */
'use strict';

const threadStates = new Map();

/* Branch-related mnemonics (x86/x64) */
const BRANCH_MNEMONICS = new Set([
    'cmp', 'test',
    'ja', 'jae', 'jb', 'jbe', 'jc', 'je', 'jg', 'jge', 'jl', 'jle',
    'jna', 'jnae', 'jnb', 'jnbe', 'jnc', 'jne', 'jng', 'jnge', 'jnl',
    'jnle', 'jno', 'jnp', 'jns', 'jnz', 'jo', 'jp', 'jpe', 'jpo',
    'js', 'jz', 'jmp', 'jcxz', 'jecxz', 'jrcxz',
    'cmove', 'cmovne', 'cmovg', 'cmovge', 'cmovl', 'cmovle',
    'cmova', 'cmovae', 'cmovb', 'cmovbe',
]);

function isBranch(mnemonic) {
    return BRANCH_MNEMONICS.has(mnemonic);
}

function isMemoryRead(instruction) {
    return instruction.operands.some(op => op.type === 'mem' && op.access.includes('r'));
}

/**
 * Build a callout function that, at runtime, computes the effective address
 * of a memory-read operand and checks if it falls within the recv buffer.
 *
 * We extract the register names from the operand at transform time (static)
 * and read their runtime values inside the callout via CpuContext.
 */
function makeBufferCheckCallout(instruction, state) {
    const mnemonic = instruction.mnemonic;
    const isBranchInstr = isBranch(mnemonic);

    /* Find the memory-read operand to compute effective address */
    let memOp = null;
    for (const op of instruction.operands) {
        if (op.type === 'mem' && op.access.includes('r')) {
            memOp = op.value;
            break;
        }
    }

    /* Extract static operand info for EA computation:
       EA = base + index * scale + disp */
    const baseReg = memOp && memOp.base ? memOp.base : null;
    const indexReg = memOp && memOp.index ? memOp.index : null;
    const scale = memOp && memOp.scale ? memOp.scale : 1;
    const disp = memOp && memOp.disp ? memOp.disp : 0;

    return function (context) {
        try {
            const bufStart = state.buffer;
            const bufEnd = bufStart.add(state.size);

            let ea = ptr(disp);
            if (baseReg) {
                const baseVal = context[baseReg];
                if (baseVal) ea = ea.add(baseVal);
            }
            if (indexReg) {
                const indexVal = context[indexReg];
                if (indexVal) ea = ea.add(ptr(indexVal).mul ? ptr(indexVal) : indexVal);
            }

            const inBuffer = ea.compare(bufStart) >= 0 && ea.compare(bufEnd) < 0;

            if (inBuffer) {
                const offset = ea.sub(bufStart).toInt32();
                send({
                    type: 'instruction',
                    payload: {
                        type: 'buffer_access',
                        mnemonic: mnemonic,
                        offset: offset
                    }
                });
            } else if (isBranchInstr) {
                send({
                    type: 'instruction',
                    payload: {
                        type: 'branch',
                        mnemonic: mnemonic,
                        offset: null
                    }
                });
            } else {
                send({
                    type: 'instruction',
                    payload: {
                        type: 'instruction',
                        mnemonic: mnemonic
                    }
                });
            }
        } catch (e) {
            /* Swallow errors in hot path to avoid crashing Stalker */
        }
    };
}

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
                        isStalking: false,
                        msghdr_ptr: null
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

                    if (bytesRead <= 0 || !state) {
                        return;
                    }

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
                            } catch (e) { /* Ignore */ }
                        }
                    }

                    if (state.buffer.isNull()) {
                        return;
                    }

                    state.size = bytesRead;

                    /* Log the buffer metadata so downstream knows the recv size */
                    send({
                        type: 'instruction',
                        payload: {
                            type: 'recv_event',
                            buffer_size: bytesRead
                        }
                    });

                    Stalker.follow(threadId, {
                        transform: function (iterator) {
                            let instruction;
                            while ((instruction = iterator.next()) !== null) {
                                const mnemonic = instruction.mnemonic;
                                const memRead = isMemoryRead(instruction);
                                const branch = isBranch(mnemonic);

                                if (memRead) {
                                    /* Use putCallout for runtime address resolution */
                                    iterator.putCallout(makeBufferCheckCallout(instruction, state));
                                } else if (branch) {
                                    /* Branch without memory-read: log statically */
                                    send({
                                        type: 'instruction',
                                        payload: {
                                            type: 'branch',
                                            mnemonic: mnemonic,
                                            offset: null
                                        }
                                    });
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
        send({ type: 'log', payload: `[SUCCESS] Successfully attached to ${hook_count} recv* functions.` });
    } else {
        send({ type: 'error', payload: 'Could not find any recv* functions to hook.' });
    }

} catch (error) {
    send({ type: 'error', payload: `[FATAL ERROR] A top-level error occurred: ${error.message}` });
}
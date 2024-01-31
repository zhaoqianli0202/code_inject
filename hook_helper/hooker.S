#include "hooker.h"

.text

/* universal stack constraint: (SP mod 16) == 0 */
/* frame pointer was saved in the trampoline */
GLOBAL(inject_entry)
	mov x29, sp
	/* save all caller-saved registers due to -fipa-ra */
	stp	x14, x15, [sp, #-16]!
	stp	x12, x13, [sp, #-16]!
	stp	x10, x11, [sp, #-16]!

	/* platform register and/or scratch registers */
	stp	x8, x9, [sp, #-16]!

	/* also save original child address for find_org_code */
	stp	x29, x30, [sp, #-16]!

	/* save arguments */
	stp	x6, x7, [sp, #-16]!
	stp	x4, x5, [sp, #-16]!
	stp	x2, x3, [sp, #-16]!
	stp	x0, x1, [sp, #-16]!

	stp	d0, d1, [sp, #-16]!

	add	x0, x29, #8
	add	x1, sp, #16
	mov x2, x30
	bl	inline_func_entry
	/*save return*/
	str x0, [sp, #-16]!

	ldr	x0, [sp, #104]
	bl	find_org_code
	str	x0, [sp, #104]

	ldr x18, [sp], #16

	ldp	d0, d1, [sp], #16

	/* restore arguments */
	ldp	x0, x1, [sp], #16
	ldp	x2, x3, [sp], #16
	ldp	x4, x5, [sp], #16
	ldp	x6, x7, [sp], #16

	/* actual return address from find_org_code() */
	ldp	x16, x17, [sp], #16

	ldp	x8, x9, [sp], #16

	/* caller-saved registers */
	ldp	x10, x11, [sp], #16
	ldp	x12, x13, [sp], #16
	ldp	x14, x15, [sp], #16

	/* restore frame pointer */
	ldp	x29, x30, [sp], #16

	/* jump to the saved insn */
	CBNZ x17, org_insn
	/*use inline_func_entry as return*/
	mov x0, x18
	ret

org_insn:
	br x17

END(inject_entry)

GLOBAL(inject_return)
	/* setup frame pointer */
	stp	x29, x30, [sp, #-16]!

	/* save all caller-saved registers due to -fipa-ra */
	stp	x14, x15, [sp, #-16]!
	stp	x12, x13, [sp, #-16]!
	stp	x10, x11, [sp, #-16]!

	/*
	 * save indirect result location register
	 * used in C++ for returning non-trivial objects
	 */
	stp	x8, x9, [sp, #-16]!

	/* caller-saved registers again */
	stp	x6, x7, [sp, #-16]!
	stp	x4, x5, [sp, #-16]!
	stp	x2, x3, [sp, #-16]!

	/* save return values */
	stp	x0, x1, [sp, #-16]!
	stp	d0, d1, [sp, #-16]!

	add	x0, sp, #16
	bl	inline_func_exit
	mov	x16, x0

	/* restore return values */
	ldp	d0, d1, [sp], #16
	ldp	x0, x1, [sp], #16

	/* restore caller-saved registers */
	ldp	x2, x3, [sp], #16
	ldp	x4, x5, [sp], #16
	ldp	x6, x7, [sp], #16

	/* restore indirect result location register */
	ldp	x8, x9, [sp], #16

	/* caller-saved registers again */
	ldp	x10, x11, [sp], #16
	ldp	x12, x13, [sp], #16
	ldp	x14, x15, [sp], #16

	/* restore frame pointer */
	ldp	x29, x30, [sp], #16

	br	x16
END(inject_return)
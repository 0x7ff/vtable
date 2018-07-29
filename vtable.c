#include <fcntl.h>
#include <inttypes.h>
#include <mach-o/loader.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define OSMETACLASS_IDX (1)
#define METACLASS_ALLOC_IDX (12)
#define IS_IN_RANGE(a, b, c) ((a) >= (b) && (a) <= (c))
#define UNTAG_PTR(a) ((a) | 0xffff000000000000ull)
#define RD(a) extract32(a, 0, 5)
#define RM(a) extract32(a, 16, 5)
#define RN(a) extract32(a, 5, 5)
#define IS_BL(a) (((a) & 0xfc000000u) == 0x94000000u)
#define BL_IMM(a) (sextract64(a, 0, 26) << 2u)
#define IS_ADRP(a) (((a) & 0x9f000000u) == 0x90000000u)
#define ADRP_IMM(a) (((sextract64(a, 5, 19) << 2u) | extract32(a, 29, 2)) << 12u)
#define ADRP_ADDR(a) ((a) & ~0xfffull)
#define IS_ADD_X(a) (((a) & 0xffc00000u) == 0x91000000u)
#define ADD_X_IMM(a) extract32(a, 10, 12)
#define IS_STR_X(a) (((a) & 0xfffffc00u) == 0xf9000000u)
#define IS_MOV_X(a) (((a) & 0xffe00000u) == 0xaa000000u)
#define IS_RET(a) ((a) == 0xd65f03c0u)

static inline uint32_t
extract32(uint32_t value, unsigned start, unsigned length) {
	return (value >> start) & (~0u >> (32u - length));
}

static inline uint64_t
sextract64(uint64_t value, unsigned start, unsigned length) {
	return (uint64_t)((int64_t)(value << (64u - length - start)) >> (64u - length));
}

static const struct segment_command_64 *
find_segment(const struct mach_header_64 *mhp, const char *seg_name) {
	const struct segment_command_64 *sgp = (const struct segment_command_64 *)((uintptr_t)mhp + sizeof(*mhp));
	uint32_t i;
	
	for(i = 0; i < mhp->ncmds; ++i) {
		if(sgp->cmd == LC_SEGMENT_64 && !strncmp(sgp->segname, seg_name, sizeof(sgp->segname))) {
			return sgp;
		}
		sgp = (const struct segment_command_64 *)((uintptr_t)sgp + sgp->cmdsize);
	}
	return NULL;
}

static const struct section_64 *
find_section_type(const struct segment_command_64 *sgp, uint8_t type) {
	const struct section_64 *sp = (const struct section_64 *)((uintptr_t)sgp + sizeof(*sgp));
	uint32_t i;
	
	for(i = 0; i < sgp->nsects; ++i) {
		if((sp->flags & SECTION_TYPE) == type) {
			return sp;
		}
		++sp;
	}
	return NULL;
}

static const struct section_64 *
find_section_name(const struct segment_command_64 *sgp, const char *sect_name) {
	const struct section_64 *sp = (const struct section_64 *)((uintptr_t)sgp + sizeof(*sgp));
	uint32_t i;
	
	for(i = 0; i < sgp->nsects; ++i) {
		if(!strncmp(sp->segname, sgp->segname, sizeof(sp->segname)) && !strncmp(sp->sectname, sect_name, sizeof(sp->sectname))) {
			return sp;
		}
		++sp;
	}
	return NULL;
}

static const struct section_64 *
find_section_type_from_seg(const struct mach_header_64 *mhp, const char *seg_name, uint8_t type) {
	const struct segment_command_64 *sgp;
	
	if((sgp = find_segment(mhp, seg_name))) {
		return find_section_type(sgp, type);
	}
	return NULL;
}

static const struct section_64 *
find_section_name_from_seg(const struct mach_header_64 *mhp, const char *seg_name, const char *sect_name) {
	const struct segment_command_64 *sgp;
	
	if((sgp = find_segment(mhp, seg_name))) {
		return find_section_name(sgp, sect_name);
	}
	return NULL;
}

static uint64_t
find_osmetaclass(const struct mach_header_64 *mhp, uint64_t slide, uint64_t sec_text_end) {
	const struct section_64 *sec_mod_init_func;
	const uint64_t *mod_init_func_table;
	const uint32_t *insn;
	uint64_t i, osmetaclass_ptr;
	
	if((sec_mod_init_func = find_section_type_from_seg(mhp, "__DATA_CONST", S_MOD_INIT_FUNC_POINTERS))) {
		mod_init_func_table = (const uint64_t *)((uintptr_t)mhp + (UNTAG_PTR(sec_mod_init_func->addr) - slide));
		osmetaclass_ptr = UNTAG_PTR(mod_init_func_table[OSMETACLASS_IDX]);
		insn = (const uint32_t *)((uintptr_t)mhp + (osmetaclass_ptr - slide));
		for(i = 0; i < (sec_text_end - osmetaclass_ptr) / sizeof(*insn); ++i) {
			if(IS_BL(insn[i])) {
				return osmetaclass_ptr + (i * sizeof(*insn)) + BL_IMM(insn[i]);
			}
		}
	}
	return 0;
}

static void
do_metaclass_alloc(const struct mach_header_64 *mhp, uint64_t ptr, uint64_t slide, uint64_t sec_text_end) {
	const uint32_t *insn;
	uint64_t i, x[32] = { 0 };
	
	insn = (const uint32_t *)((uintptr_t)mhp + (ptr - slide));
	for(i = 0; i < (sec_text_end - ptr) / sizeof(*insn); ++i) {
		if(IS_ADRP(insn[i])) {
			x[RD(insn[i])] = ADRP_ADDR(ptr + (i * sizeof(*insn))) + ADRP_IMM(insn[i]);
		} else if(IS_ADD_X(insn[i])) {
			x[RD(insn[i])] = x[RN(insn[i])] + ADD_X_IMM(insn[i]);
		} else if(IS_STR_X(insn[i])) {
			printf(", vtable: 0x%016" PRIx64, x[RD(insn[i])]);
			break;
		} else if(IS_RET(insn[i])) {
			break;
		}
	}
}

static void
do_kmod_init(const struct mach_header_64 *mhp, uint64_t len, uint64_t ptr, uint64_t slide, uint64_t cstring_start, uint64_t cstring_end, uint64_t sec_text_start, uint64_t sec_text_end, uint64_t osmetaclass) {
	const uint64_t *metaclass_table;
	const uint32_t *insn;
	uint64_t i, off, addr, x[32] = { 0 };
	bool found = false;
	
	insn = (const uint32_t *)((uintptr_t)mhp + (ptr - slide));
	for(i = 0; i < (sec_text_end - ptr) / sizeof(*insn); ++i) {
		if(IS_BL(insn[i])) {
			addr = ptr + (i * sizeof(*insn)) + BL_IMM(insn[i]);
			found = (addr == osmetaclass);
		} else if(IS_ADRP(insn[i])) {
			x[RD(insn[i])] = ADRP_ADDR(ptr + (i * sizeof(*insn))) + ADRP_IMM(insn[i]);
		} else if(IS_ADD_X(insn[i])) {
			x[RD(insn[i])] = x[RN(insn[i])] + ADD_X_IMM(insn[i]);
		} else if(IS_MOV_X(insn[i])) {
			x[RD(insn[i])] = x[RM(insn[i])];
		} else if(found && IS_STR_X(insn[i])) {
			if(IS_IN_RANGE(x[1], cstring_start, cstring_end)) {
				printf("Name: %s, metaclass: 0x%016" PRIx64, (const char *)((uintptr_t)mhp + (x[1] - slide)), x[RD(insn[i])]);
				off = x[RD(insn[i])] - slide;
				if((off + sizeof(uint64_t)) <= len) {
					metaclass_table = (const uint64_t *)((uintptr_t)mhp + off);
					addr = UNTAG_PTR(metaclass_table[METACLASS_ALLOC_IDX]);
					if(IS_IN_RANGE(addr, sec_text_start, sec_text_end)) {
						do_metaclass_alloc(mhp, addr, slide, sec_text_end);
					}
				}
				putchar('\n');
			}
			found = false;
		} else if(IS_RET(insn[i])) {
			break;
		}
	}
}

static void
vtable(const struct mach_header_64 *mhp, uint64_t len) {
	const struct section_64 *sec_text, *sec_cstring, *sec_kmod_init;
	const struct segment_command_64 *seg_text;
	const uint64_t *func_table;
	uint64_t i, cstring_end, sec_text_end, osmetaclass;
	
	if((sec_kmod_init = find_section_type_from_seg(mhp, SEG_DATA, S_MOD_INIT_FUNC_POINTERS)) &&
	   (seg_text = find_segment(mhp, SEG_TEXT)) &&
	   (sec_cstring = find_section_type(seg_text, S_CSTRING_LITERALS)) &&
	   (sec_text = find_section_name_from_seg(mhp, "__TEXT_EXEC", SECT_TEXT)))
	{
		sec_text_end = sec_text->addr + sec_text->size;
		if((osmetaclass = find_osmetaclass(mhp, seg_text->vmaddr, sec_text_end))) {
			func_table = (const uint64_t *)((uintptr_t)mhp + sec_kmod_init->offset);
			cstring_end = sec_cstring->addr + sec_cstring->size;
			
			for(i = 0; i < sec_kmod_init->size / sizeof(*func_table); ++i) {
				do_kmod_init(mhp, len, UNTAG_PTR(func_table[i]), seg_text->vmaddr, sec_cstring->addr, cstring_end, sec_text->addr, sec_text_end, osmetaclass);
			}
		}
	}
}

int
main(int argc, char **argv) {
	if(argc != 2) {
		printf("Usage: %s kernel\n", argv[0]);
	} else {
		int fd = open(argv[1], O_RDONLY);
		size_t len = (size_t)lseek(fd, 0, SEEK_END);
		struct mach_header_64 *mhp = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
		close(fd);
		if(mhp != MAP_FAILED) {
			if(mhp->magic == MH_MAGIC_64 &&
			   mhp->cputype == CPU_TYPE_ARM64)
			{
				vtable(mhp, len);
			}
			munmap(mhp, len);
		}
	}
}

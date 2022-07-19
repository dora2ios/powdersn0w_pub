#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <patchfinder.h>

__unused static uint32_t bit_range(uint32_t x, int start, int end)
{
    x = (x << (31 - start)) >> (31 - start);
    x = (x >> end);
    return x;
}

__unused static uint32_t ror(uint32_t x, int places)
{
    return (x >> places) | (x << (32 - places));
}

__unused static int thumb_expand_imm_c(uint16_t imm12)
{
    if(bit_range(imm12, 11, 10) == 0)
    {
        switch(bit_range(imm12, 9, 8))
        {
            case 0:
                return bit_range(imm12, 7, 0);
            case 1:
                return (bit_range(imm12, 7, 0) << 16) | bit_range(imm12, 7, 0);
            case 2:
                return (bit_range(imm12, 7, 0) << 24) | (bit_range(imm12, 7, 0) << 8);
            case 3:
                return (bit_range(imm12, 7, 0) << 24) | (bit_range(imm12, 7, 0) << 16) | (bit_range(imm12, 7, 0) << 8) | bit_range(imm12, 7, 0);
            default:
                return 0;
        }
    } else
    {
        uint32_t unrotated_value = 0x80 | bit_range(imm12, 6, 0);
        return ror(unrotated_value, bit_range(imm12, 11, 7));
    }
}

int insn_is_32bit(uint16_t* i)
{
    return (*i & 0xe000) == 0xe000 && (*i & 0x1800) != 0x0;
}

__unused static int insn_is_bl(uint16_t* i)
{
    if((*i & 0xf800) == 0xf000 && (*(i + 1) & 0xd000) == 0xd000)
        return 1;
    else if((*i & 0xf800) == 0xf000 && (*(i + 1) & 0xd001) == 0xc000)
        return 1;
    else
        return 0;
}

__unused static uint32_t insn_bl_imm32(uint16_t* i)
{
    uint16_t insn0 = *i;
    uint16_t insn1 = *(i + 1);
    uint32_t s = (insn0 >> 10) & 1;
    uint32_t j1 = (insn1 >> 13) & 1;
    uint32_t j2 = (insn1 >> 11) & 1;
    uint32_t i1 = ~(j1 ^ s) & 1;
    uint32_t i2 = ~(j2 ^ s) & 1;
    uint32_t imm10 = insn0 & 0x3ff;
    uint32_t imm11 = insn1 & 0x7ff;
    uint32_t imm32 = (imm11 << 1) | (imm10 << 12) | (i2 << 22) | (i1 << 23) | (s ? 0xff000000 : 0);
    return imm32;
}

__unused static int insn_is_b_conditional(uint16_t* i)
{
    return (*i & 0xF000) == 0xD000 && (*i & 0x0F00) != 0x0F00 && (*i & 0x0F00) != 0xE;
}

__unused static int insn_is_b_unconditional(uint16_t* i)
{
    if((*i & 0xF800) == 0xE000)
        return 1;
    else if((*i & 0xF800) == 0xF000 && (*(i + 1) & 0xD000) == 9)
        return 1;
    else
        return 0;
}

__unused static int insn_is_ldr_literal(uint16_t* i)
{
    return (*i & 0xF800) == 0x4800 || (*i & 0xFF7F) == 0xF85F;
}

__unused static int insn_ldr_literal_rt(uint16_t* i)
{
    if((*i & 0xF800) == 0x4800)
        return (*i >> 8) & 7;
    else if((*i & 0xFF7F) == 0xF85F)
        return (*(i + 1) >> 12) & 0xF;
    else
        return -1;
}

__unused static int insn_ldr_literal_imm(uint16_t* i)
{
    if((*i & 0xF800) == 0x4800)
        return (*i & 0xFF) << 2;
    else if((*i & 0xFF7F) == 0xF85F)
        return (*(i + 1) & 0xFFF) * (((*i & 0x0800) == 0x0800) ? 1 : -1);
    else
        return 0;
}

// TODO: More encodings
__unused static int insn_is_ldr_imm(uint16_t* i)
{
    uint8_t opA = bit_range(*i, 15, 12);
    uint8_t opB = bit_range(*i, 11, 9);
    
    return opA == 6 && (opB & 4) == 4;
}

__unused static int insn_ldr_imm_rt(uint16_t* i)
{
    return (*i & 7);
}

__unused static int insn_ldr_imm_rn(uint16_t* i)
{
    return ((*i >> 3) & 7);
}

__unused static int insn_ldr_imm_imm(uint16_t* i)
{
    return ((*i >> 6) & 0x1F);
}

// TODO: More encodings
__unused static int insn_is_ldrb_imm(uint16_t* i)
{
    return (*i & 0xF800) == 0x7800;
}

__unused static int insn_ldrb_imm_rt(uint16_t* i)
{
    return (*i & 7);
}

__unused static int insn_ldrb_imm_rn(uint16_t* i)
{
    return ((*i >> 3) & 7);
}

__unused static int insn_ldrb_imm_imm(uint16_t* i)
{
    return ((*i >> 6) & 0x1F);
}

__unused __unused static int insn_is_ldr_reg(uint16_t* i)
{
    if((*i & 0xFE00) == 0x5800)
        return 1;
    else if((*i & 0xFFF0) == 0xF850 && (*(i + 1) & 0x0FC0) == 0x0000)
        return 1;
    else
        return 0;
}

__unused __unused static int insn_ldr_reg_rn(uint16_t* i)
{
    if((*i & 0xFE00) == 0x5800)
        return (*i >> 3) & 0x7;
    else if((*i & 0xFFF0) == 0xF850 && (*(i + 1) & 0x0FC0) == 0x0000)
        return (*i & 0xF);
    else
        return 0;
}

int insn_ldr_reg_rt(uint16_t* i)
{
    if((*i & 0xFE00) == 0x5800)
        return *i & 0x7;
    else if((*i & 0xFFF0) == 0xF850 && (*(i + 1) & 0x0FC0) == 0x0000)
        return (*(i + 1) >> 12) & 0xF;
    else
        return 0;
}

int insn_ldr_reg_rm(uint16_t* i)
{
    if((*i & 0xFE00) == 0x5800)
        return (*i >> 6) & 0x7;
    else if((*i & 0xFFF0) == 0xF850 && (*(i + 1) & 0x0FC0) == 0x0000)
        return *(i + 1) & 0xF;
    else
        return 0;
}

__unused __unused static int insn_ldr_reg_lsl(uint16_t* i)
{
    if((*i & 0xFE00) == 0x5800)
        return 0;
    else if((*i & 0xFFF0) == 0xF850 && (*(i + 1) & 0x0FC0) == 0x0000)
        return (*(i + 1) >> 4) & 0x3;
    else
        return 0;
}

__unused static int insn_is_add_reg(uint16_t* i)
{
    if((*i & 0xFE00) == 0x1800)
        return 1;
    else if((*i & 0xFF00) == 0x4400)
        return 1;
    else if((*i & 0xFFE0) == 0xEB00)
        return 1;
    else
        return 0;
}

__unused static int insn_add_reg_rd(uint16_t* i)
{
    if((*i & 0xFE00) == 0x1800)
        return (*i & 7);
    else if((*i & 0xFF00) == 0x4400)
        return (*i & 7) | ((*i & 0x80) >> 4) ;
    else if((*i & 0xFFE0) == 0xEB00)
        return (*(i + 1) >> 8) & 0xF;
    else
        return 0;
}

__unused static int insn_add_reg_rn(uint16_t* i)
{
    if((*i & 0xFE00) == 0x1800)
        return ((*i >> 3) & 7);
    else if((*i & 0xFF00) == 0x4400)
        return (*i & 7) | ((*i & 0x80) >> 4) ;
    else if((*i & 0xFFE0) == 0xEB00)
        return (*i & 0xF);
    else
        return 0;
}

__unused static int insn_add_reg_rm(uint16_t* i)
{
    if((*i & 0xFE00) == 0x1800)
        return (*i >> 6) & 7;
    else if((*i & 0xFF00) == 0x4400)
        return (*i >> 3) & 0xF;
    else if((*i & 0xFFE0) == 0xEB00)
        return *(i + 1) & 0xF;
    else
        return 0;
}

__unused static int insn_is_movt(uint16_t* i)
{
    return (*i & 0xFBF0) == 0xF2C0 && (*(i + 1) & 0x8000) == 0;
}

__unused static int insn_movt_rd(uint16_t* i)
{
    return (*(i + 1) >> 8) & 0xF;
}

__unused static int insn_movt_imm(uint16_t* i)
{
    return ((*i & 0xF) << 12) | ((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF);
}

__unused static int insn_is_mov_imm(uint16_t* i)
{
    if((*i & 0xF800) == 0x2000)
        return 1;
    else if((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return 1;
    else if((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return 1;
    else
        return 0;
}

__unused static int insn_mov_imm_rd(uint16_t* i)
{
    if((*i & 0xF800) == 0x2000)
        return (*i >> 8) & 7;
    else if((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return (*(i + 1) >> 8) & 0xF;
    else if((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return (*(i + 1) >> 8) & 0xF;
    else
        return 0;
}

__unused static int insn_mov_imm_imm(uint16_t* i)
{
    if((*i & 0xF800) == 0x2000)
        return *i & 0xF;
    else if((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return thumb_expand_imm_c(((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF));
    else if((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return ((*i & 0xF) << 12) | ((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF);
    else
        return 0;
}

__unused __unused static int insn_is_cmp_imm(uint16_t* i)
{
    if((*i & 0xF800) == 0x2800)
        return 1;
    else if((*i & 0xFBF0) == 0xF1B0 && (*(i + 1) & 0x8F00) == 0x0F00)
        return 1;
    else
        return 0;
}

__unused __unused static int insn_cmp_imm_rn(uint16_t* i)
{
    if((*i & 0xF800) == 0x2800)
        return (*i >> 8) & 7;
    else if((*i & 0xFBF0) == 0xF1B0 && (*(i + 1) & 0x8F00) == 0x0F00)
        return *i & 0xF;
    else
        return 0;
}

__unused __unused static int insn_cmp_imm_imm(uint16_t* i)
{
    if((*i & 0xF800) == 0x2800)
        return *i & 0xFF;
    else if((*i & 0xFBF0) == 0xF1B0 && (*(i + 1) & 0x8F00) == 0x0F00)
        return thumb_expand_imm_c(((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF));
    else
        return 0;
}

__unused __unused static int insn_is_and_imm(uint16_t* i)
{
    return (*i & 0xFBE0) == 0xF000 && (*(i + 1) & 0x8000) == 0;
}

__unused __unused static int insn_and_imm_rn(uint16_t* i)
{
    return *i & 0xF;
}

__unused __unused static int insn_and_imm_rd(uint16_t* i)
{
    return (*(i + 1) >> 8) & 0xF;
}

__unused __unused static int insn_and_imm_imm(uint16_t* i)
{
    return thumb_expand_imm_c(((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF));
}

__unused static int insn_is_push(uint16_t* i)
{
    if((*i & 0xFE00) == 0xB400)
        return 1;
    else if(*i == 0xE92D)
        return 1;
    else if(*i == 0xF84D && (*(i + 1) & 0x0FFF) == 0x0D04)
        return 1;
    else
        return 0;
}

__unused static int insn_push_registers(uint16_t* i)
{
    if((*i & 0xFE00) == 0xB400)
        return (*i & 0x00FF) | ((*i & 0x0100) << 6);
    else if(*i == 0xE92D)
        return *(i + 1);
    else if(*i == 0xF84D && (*(i + 1) & 0x0FFF) == 0x0D04)
        return 1 << ((*(i + 1) >> 12) & 0xF);
    else
        return 0;
}

__unused static int insn_is_preamble_push(uint16_t* i)
{
    return insn_is_push(i) && (insn_push_registers(i) & (1 << 14)) != 0;
}

__unused static int insn_is_str_imm(uint16_t* i)
{
    if((*i & 0xF800) == 0x6000)
        return 1;
    else if((*i & 0xF800) == 0x9000)
        return 1;
    else if((*i & 0xFFF0) == 0xF8C0)
        return 1;
    else if((*i & 0xFFF0) == 0xF840 && (*(i + 1) & 0x0800) == 0x0800)
        return 1;
    else
        return 0;
}

__unused static int insn_str_imm_postindexed(uint16_t* i)
{
    if((*i & 0xF800) == 0x6000)
        return 1;
    else if((*i & 0xF800) == 0x9000)
        return 1;
    else if((*i & 0xFFF0) == 0xF8C0)
        return 1;
    else if((*i & 0xFFF0) == 0xF840 && (*(i + 1) & 0x0800) == 0x0800)
        return (*(i + 1) >> 10) & 1;
    else
        return 0;
}

__unused static int insn_str_imm_wback(uint16_t* i)
{
    if((*i & 0xF800) == 0x6000)
        return 0;
    else if((*i & 0xF800) == 0x9000)
        return 0;
    else if((*i & 0xFFF0) == 0xF8C0)
        return 0;
    else if((*i & 0xFFF0) == 0xF840 && (*(i + 1) & 0x0800) == 0x0800)
        return (*(i + 1) >> 8) & 1;
    else
        return 0;
}

__unused static int insn_str_imm_imm(uint16_t* i)
{
    if((*i & 0xF800) == 0x6000)
        return (*i & 0x07C0) >> 4;
    else if((*i & 0xF800) == 0x9000)
        return (*i & 0xFF) << 2;
    else if((*i & 0xFFF0) == 0xF8C0)
        return (*(i + 1) & 0xFFF);
    else if((*i & 0xFFF0) == 0xF840 && (*(i + 1) & 0x0800) == 0x0800)
        return (*(i + 1) & 0xFF);
    else
        return 0;
}

__unused static int insn_str_imm_rt(uint16_t* i)
{
    if((*i & 0xF800) == 0x6000)
        return (*i & 7);
    else if((*i & 0xF800) == 0x9000)
        return (*i >> 8) & 7;
    else if((*i & 0xFFF0) == 0xF8C0)
        return (*(i + 1) >> 12) & 0xF;
    else if((*i & 0xFFF0) == 0xF840 && (*(i + 1) & 0x0800) == 0x0800)
        return (*(i + 1) >> 12) & 0xF;
    else
        return 0;
}

__unused static int insn_str_imm_rn(uint16_t* i)
{
    if((*i & 0xF800) == 0x6000)
        return (*i >> 3) & 7;
    else if((*i & 0xF800) == 0x9000)
        return 13;
    else if((*i & 0xFFF0) == 0xF8C0)
        return (*i & 0xF);
    else if((*i & 0xFFF0) == 0xF840 && (*(i + 1) & 0x0800) == 0x0800)
        return (*i & 0xF);
    else
        return 0;
}

// Given an instruction, search backwards until an instruction is found matching the specified criterion.
__unused static uint16_t* find_last_insn_matching(uint32_t region, uint8_t* kdata, size_t ksize, uint16_t* current_instruction, int (*match_func)(uint16_t*))
{
    while((uintptr_t)current_instruction > (uintptr_t)kdata)
    {
        if(insn_is_32bit(current_instruction - 2) && !insn_is_32bit(current_instruction - 3))
        {
            current_instruction -= 2;
        } else
        {
            --current_instruction;
        }
        
        if(match_func(current_instruction))
        {
            return current_instruction;
        }
    }
    
    return NULL;
}

// Given an instruction and a register, find the PC-relative address that was stored inside the register by the time the instruction was reached.
__unused static uint32_t find_pc_rel_value(uint32_t region, uint8_t* kdata, size_t ksize, uint16_t* insn, int reg)
{
    // Find the last instruction that completely wiped out this register
    int found = 0;
    uint16_t* current_instruction = insn;
    while((uintptr_t)current_instruction > (uintptr_t)kdata)
    {
        if(insn_is_32bit(current_instruction - 2))
        {
            current_instruction -= 2;
        } else
        {
            --current_instruction;
        }
        
        if(insn_is_mov_imm(current_instruction) && insn_mov_imm_rd(current_instruction) == reg)
        {
            found = 1;
            break;
        }
        
        if(insn_is_ldr_literal(current_instruction) && insn_ldr_literal_rt(current_instruction) == reg)
        {
            found = 1;
            break;
        }
    }
    
    if(!found)
        return 0;
    
    // Step through instructions, executing them as a virtual machine, only caring about instructions that affect the target register and are commonly used for PC-relative addressing.
    uint32_t value = 0;
    while((uintptr_t)current_instruction < (uintptr_t)insn)
    {
        if(insn_is_mov_imm(current_instruction) && insn_mov_imm_rd(current_instruction) == reg)
        {
            value = insn_mov_imm_imm(current_instruction);
        } else if(insn_is_ldr_literal(current_instruction) && insn_ldr_literal_rt(current_instruction) == reg)
        {
            value = *(uint32_t*)(kdata + (((((uintptr_t)current_instruction - (uintptr_t)kdata) + 4) & 0xFFFFFFFC) + insn_ldr_literal_imm(current_instruction)));
        } else if(insn_is_movt(current_instruction) && insn_movt_rd(current_instruction) == reg)
        {
            value |= insn_movt_imm(current_instruction) << 16;
        } else if(insn_is_add_reg(current_instruction) && insn_add_reg_rd(current_instruction) == reg)
        {
            if(insn_add_reg_rm(current_instruction) != 15 || insn_add_reg_rn(current_instruction) != reg)
            {
                // Can't handle this kind of operation!
                return 0;
            }
            
            value += ((uintptr_t)current_instruction - (uintptr_t)kdata) + 4;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    
    return value;
}

// Find PC-relative references to a certain address (relative to kdata). This is basically a virtual machine that only cares about instructions used in PC-relative addressing, so no branches, etc.
__unused static uint16_t* find_literal_ref(uint32_t region, uint8_t* kdata, size_t ksize, uint16_t* insn, uint32_t address)
{
    uint16_t* current_instruction = insn;
    uint32_t value[16];
    memset(value, 0, sizeof(value));
    
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_mov_imm(current_instruction))
        {
            value[insn_mov_imm_rd(current_instruction)] = insn_mov_imm_imm(current_instruction);
        } else if(insn_is_ldr_literal(current_instruction))
        {
            uintptr_t literal_address  = (uintptr_t)kdata + ((((uintptr_t)current_instruction - (uintptr_t)kdata) + 4) & 0xFFFFFFFC) + insn_ldr_literal_imm(current_instruction);
            if(literal_address >= (uintptr_t)kdata && (literal_address + 4) <= ((uintptr_t)kdata + ksize))
            {
                value[insn_ldr_literal_rt(current_instruction)] = *(uint32_t*)(literal_address);
            }
        } else if(insn_is_movt(current_instruction))
        {
            int reg = insn_movt_rd(current_instruction);
            value[reg] |= insn_movt_imm(current_instruction) << 16;
            if(value[reg] == address)
            {
                return current_instruction;
            }
        } else if(insn_is_add_reg(current_instruction))
        {
            int reg = insn_add_reg_rd(current_instruction);
            if(insn_add_reg_rm(current_instruction) == 15 && insn_add_reg_rn(current_instruction) == reg)
            {
                value[reg] += ((uintptr_t)current_instruction - (uintptr_t)kdata) + 4;
                if(value[reg] == address)
                {
                    return current_instruction;
                }
            }
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    
    return NULL;
}

struct find_search_mask
{
    uint16_t mask;
    uint16_t value;
};

// Search the range of kdata for a series of 16-bit values that match the search mask.
__unused static uint16_t* find_with_search_mask(uint32_t region, uint8_t* kdata, size_t ksize, int num_masks, const struct find_search_mask* masks)
{
    uint16_t* end = (uint16_t*)(kdata + ksize - (num_masks * sizeof(uint16_t)));
    uint16_t* cur;
    for(cur = (uint16_t*) kdata; cur <= end; ++cur)
    {
        int matched = 1;
        int i;
        for(i = 0; i < num_masks; ++i)
        {
            if((*(cur + i) & masks[i].mask) != masks[i].value)
            {
                matched = 0;
                break;
            }
        }
        
        if(matched)
            return cur;
    }
    
    return NULL;
}

unsigned int make_b_w(int pos, int tgt)
{
    int delta;
    unsigned int i;
    unsigned short pfx;
    unsigned short sfx;
    
    unsigned int omask_1k = 0xB800;
    unsigned int omask_2k = 0xB000;
    unsigned int omask_3k = 0x9800;
    unsigned int omask_4k = 0x9000;
    
    unsigned int amask = 0x7FF;
    int range;
    
    range = 0x400000;
    
    delta = tgt - pos - 4; /* range: 0x400000 */
    i = 0;
    if(tgt > pos) i = tgt - pos - 4;
    if(tgt < pos) i = pos - tgt - 4;
    
    if (i < range){
        pfx = 0xF000 | ((delta >> 12) & 0x7FF);
        sfx =  omask_1k | ((delta >>  1) & amask);
        
        return (unsigned int)pfx | ((unsigned int)sfx << 16);
    }
    
    if (range < i && i < range*2){
        delta -= range;
        pfx = 0xF000 | ((delta >> 12) & 0x7FF);
        sfx =  omask_2k | ((delta >>  1) & amask);
        
        return (unsigned int)pfx | ((unsigned int)sfx << 16);
    }
    
    if (range*2 < i && i < range*3){
        delta -= range*2;
        pfx = 0xF000 | ((delta >> 12) & 0x7FF);
        sfx =  omask_3k | ((delta >>  1) & amask);
        
        return (unsigned int)pfx | ((unsigned int)sfx << 16);
    }
    
    if (range*3 < i && i < range*4){
        delta -= range*3;
        pfx = 0xF000 | ((delta >> 12) & 0x7FF);
        sfx =  omask_4k | ((delta >>  1) & amask);
        return (unsigned int)pfx | ((unsigned int)sfx << 16);
    }
    
    return -1;
}

uint32_t make_bl(int pos, int tgt)
{
    int delta;
    unsigned short pfx;
    unsigned short sfx;
    
    unsigned int omask = 0xF800;
    unsigned int amask = 0x07FF;
    
    delta = tgt - pos - 4; /* range: 0x400000 */
    pfx = 0xF000 | ((delta >> 12) & 0x7FF);
    sfx =  omask | ((delta >>  1) & amask);
    
    return (unsigned int)pfx | ((unsigned int)sfx << 16);
}

__unused static uint32_t find_xref_begin(uint32_t region, uint8_t* data, size_t size, const char* str)
{
    uint8_t* magicStr = memmem(data, size, str, strlen(str));
    if(!magicStr)
        return 0;
    
    uint16_t* ref = find_literal_ref(region, data, size, (uint16_t*) data, (uintptr_t)magicStr - (uintptr_t)data);
    if(!ref)
        return 0;
    
    uint16_t* pref = ref;
    pref -= 2;
    if(!insn_is_32bit(pref))
        pref += 1;
    if(insn_is_ldr_literal(pref)) {
        return (uintptr_t)pref - (uintptr_t)data;
    }
    
    uint16_t* insn = NULL;
    uint16_t* current_insn = ref;
    while((uintptr_t)current_insn < (uintptr_t)(data + size))
    {
        if(insn_is_mov_imm(current_insn))
        {
            insn = current_insn;
            break;
        }
        
        pref = current_insn;
        pref -= 2;
        if(!insn_is_32bit(pref))
            pref += 1;
        current_insn = pref;
    }
    if(!insn)
        return 0;
    
    return (uintptr_t)insn - (uintptr_t)data;
}

/* iboot */
__unused static uint16_t* find_insn_movt_rx_val(uint8_t* data, size_t size, uint16_t val)
{
    int found = 0;
    uint16_t* current_insn = (uint16_t*)data;
    
    while((uintptr_t)current_insn < (uintptr_t)(data + size))
    {
        if(insn_is_movt(current_insn) && insn_movt_imm(current_insn) == val)
        {
            found = 1;
            break;
        }
        current_insn++;
    }
    if(!found)
        return NULL;
    
    return current_insn;
}

__unused static uint16_t* find_verify_shsh_func(uint16_t* insn, uint8_t* data, size_t size)
{
    uint16_t* ref = NULL;
    uint16_t* pref = NULL;
    uint16_t* current_insn = insn;
    while((uintptr_t)current_insn < (uintptr_t)(data + size))
    {
        if(insn_is_push(current_insn) && (insn_push_registers(current_insn) & (1 << 14)) != 0)
        {
            ref = current_insn;
            break;
        }
        
        pref = current_insn;
        pref -= 2;
        if(!insn_is_32bit(pref))
            pref += 1;
        current_insn = pref;
    }
    if(!ref)
        return NULL;
    
    return ref;
}

__unused static uint16_t* find_verify_shsh_ldr_post_8(uint8_t* data, size_t size)
{
    uint16_t* insn = NULL;
    uint8_t* current_insn = data;
    for(int i=0; i<size;i+=2)
    {
        if(insn_is_ldr_literal((uint16_t*)current_insn) &&
           *(uint32_t*)(current_insn - ((((uintptr_t)current_insn - (uintptr_t)data)) & 0x3) + insn_ldr_literal_imm((uint16_t*)current_insn) + 4) == 0x43455254) {
            insn = (uint16_t*)current_insn;
            break;
        }
        current_insn += 2;
    }
    if(!insn)
        return NULL;
    
    return insn;
}


__unused static uint16_t* find_bl_insn_to(uint16_t* func, uint8_t* data, size_t size)
{
    uint32_t func_addr = (uintptr_t)func - (uintptr_t)data;
    uint32_t bl_insn_op = 0;
    
    uint16_t* insn = NULL;
    uint16_t* current_insn = (uint16_t*)data;
    for(int i=0; i<size;i+=2)
    {
        bl_insn_op = make_bl(i, func_addr);
        if(insn_is_bl(current_insn) &&
           (*(uint32_t*)current_insn == bl_insn_op)) {
            insn = current_insn;
            break;
        }
        current_insn++;
    }
    return insn;
}

__unused static uint16_t* find_ldr_xref(uint32_t region, uint8_t* data, size_t size, uint8_t* ref)
{
    uint32_t base = (uintptr_t)ref - (uintptr_t)data;
    uint32_t addr = 0;
    uint16_t* insn = NULL;
    uint8_t* current_insn = ref;
    int i = 0;
    while(i < 0x1000) // range
    {
        if(insn_is_ldr_literal((uint16_t*)current_insn) &&
           insn_is_32bit((uint16_t*)current_insn) ? ((*(uint16_t*)current_insn &~0xFFF0) == 15) : ((*(uint16_t*)current_insn & 0x4800) == 0x4800))
        {
            addr = ((uintptr_t)current_insn - (uintptr_t)data) - (((uintptr_t)current_insn - (uintptr_t)data) & 0x3) + 4; // pc
            //printf("addr %x: %x - %x\n", (uintptr_t)current_insn - (uintptr_t)data, base-addr, insn_ldr_literal_imm((uint16_t*)current_insn));
            if(insn_ldr_literal_imm((uint16_t*)current_insn) &&  (insn_ldr_literal_imm((uint16_t*)current_insn) == (base - addr))){
                insn = (uint16_t*)current_insn;
                break;
            }
        }
        
        current_insn -= 2;
        i += 2;
    }
    if(!insn)
        return NULL;
    
    return insn;
}

__unused static uint16_t* find_ldr_xref_with_str(uint32_t region, uint8_t* data, size_t size, const char* str)
{
    uint8_t* magicStr = memmem(data, size, str, strlen(str));
    if(!magicStr)
        return NULL;
    
    uint32_t search[1];
    search[0] = (uint32_t)(region + (uintptr_t)magicStr - (uintptr_t)data);
    
    uint8_t* ref = memmem(data, size, search, 4);
    if(!ref)
        return NULL;
    
    return find_ldr_xref(region, data, size, ref);
}

uint32_t find_image_passed_signature(uint32_t region, uint8_t* data, size_t size)
{
    return find_xref_begin(region, data, size, "Image passed signature verification");
}

uint32_t find_image_failed_signature(uint32_t region, uint8_t* data, size_t size)
{
    return find_xref_begin(region, data, size, "Image failed signature verification");
}

uint32_t buggy_find_csdir_magic(uint32_t region, uint8_t* data, size_t size)
{
    // 0xfade0c02
    const uint8_t search_magic[] = {0xfa, 0xde, 0x0c, 0x02};
    uint8_t* magic = memmem(data, size, search_magic, sizeof(search_magic));
    if(!magic)
        return 0;
    return (uintptr_t)magic - (uintptr_t)data;
}

int find_iboot_version(uint8_t* data, size_t size)
{
    const uint8_t search[] = {0x69, 0x42, 0x6F, 0x6F, 0x74, 0x2D};
    uint8_t* magic = memmem(data, size, search, sizeof(search));
    if(!magic)
        return 0;
    
    uint8_t* num = magic;
    num += 6;
    
    char str[32];
    memset(str, 0x0, 32);
    int i = 0;
    while((*(uint8_t*)num &~ 0x0F) == 0x30) {
        memcpy(str+i, num, 1);
        num++;
        i++;
    }
    
    return strtol(str, NULL, 0);
}

char* find_iboot_type(uint8_t* data, size_t size)
{
    uint8_t* current = data;
    current += 0x200;
    
    char* iboot_type = malloc(64);
    if (!iboot_type) {
        return NULL;
    }
    
    memset(iboot_type, 0x0, 64);
    int i = 0;
    while((*(uint8_t*)current != 0x20)) {
        memcpy(iboot_type+i, current, 1);
        current++;
        i++;
        if(i > 64)
            break;
    }
    
    return iboot_type;
}

uint32_t find_iboot_base(uint8_t* data, size_t size)
{
    uint16_t* insn = NULL;
    uint8_t* current_insn = data;
    current_insn += 0x40;
    while((uintptr_t)current_insn < (uintptr_t)(data + size))
    {
        if(*(uint16_t*)(current_insn + 2) == 0xE59F)
        {
            insn = (uint16_t*)current_insn;
            break;
        }
        current_insn += insn_is_32bit((uint16_t*)current_insn) ? 4 : 2;
    }
    if(!insn)
        return 0;
    
    uint32_t val = *(uint16_t*)(current_insn) & ~0xF000;
    current_insn += 4; // pc
    val += (uintptr_t)current_insn - (uintptr_t)data + 4;
    
    return *(uint32_t*)(data + val);
}

uint32_t find_verify_shsh(uint8_t* data, size_t size)
{
    uint16_t* insn = find_insn_movt_rx_val(data, size, 0x4345);
    if(!insn) {
        insn = find_verify_shsh_ldr_post_8(data, size);
        if(!insn)
            return 0;
    }
    
    uint16_t* func = find_verify_shsh_func(insn, data, size);
    if(!func)
        return 0;
    
    uint16_t* bl_insn = find_bl_insn_to(func, data, size);
    if(!bl_insn)
        return 0;
    
    return (uintptr_t)bl_insn - (uintptr_t)data;
}

uint32_t find_debug_enabled(uint32_t region, uint8_t* data, size_t size)
{
    uint16_t* ref = find_ldr_xref_with_str(region, data, size, "debug-enabled");
    if(!ref)
        return 0;
    
    int found = 0;
    uint16_t* insn = NULL;
    uint16_t* current_insn = ref;
    int i = 0;
    while((uintptr_t)current_insn < (uintptr_t)(data + size) && i < 0x100)
    {
        if(*(uint32_t*)current_insn == 0xbf002001)
        {
            // already patched
            break;
        }
        if(insn_is_bl(current_insn))
        {
            found += 1;
            if(found == 2) {
                insn = current_insn;
                break;
            }
        }
        
        i += insn_is_32bit(current_insn) ? 4 : 2;
        current_insn += insn_is_32bit(current_insn) ? 2 : 1;
    }
    if(!insn)
        return 0;
    
    return (uintptr_t)insn - (uintptr_t)data;
}

__unused static uint16_t* find_ticket(uint32_t region, uint8_t* data, size_t size)
{
    uint32_t search1[1];
    search1[0] = (uint32_t)(region + 0x280);
    
    uint8_t* ref1 = memmem(data, size, search1, 4);
    if(!ref1)
        return 0;
    
    uint32_t search2[1];
    search2[0] = (uint32_t)(region + (uintptr_t)ref1 - (uintptr_t)data);
    
    uint8_t* ref2 = NULL;
    uint32_t current_addr = 0;
    for(int i=0;i<3;i++) {
        ref2 = memmem(data+current_addr, size-current_addr, search2, 4);
        if(!ref2)
            return 0;
        current_addr = (uintptr_t)ref2 - (uintptr_t)data + 4;
    }
    
    uint16_t* xref = find_ldr_xref(region, data, size, ref2);
    if(!xref)
        return 0;
    
    int found = 0;
    uint16_t* insn = NULL;
    uint16_t* current_insn = xref;
    while((uintptr_t)current_insn < (uintptr_t)(data + size))
    {
        if(insn_is_bl(current_insn))
        {
            found = 1;
            insn = current_insn;
            break;
            
        }
        current_insn += insn_is_32bit(current_insn) ? 2 : 1;
    }
    if(!insn)
        return 0;
    
    return insn; // BL
}

uint32_t find_ticket1(uint32_t region, uint8_t* data, size_t size)
{
    uint16_t* bl_insn = find_ticket(region, data, size);
    if(!bl_insn)
        return 0;
    
    bl_insn += insn_is_32bit(bl_insn) ? 2 : 1;
    
    return (uintptr_t)bl_insn - (uintptr_t)data;
}

uint32_t find_ticket2(uint32_t region, uint8_t* data, size_t size)
{
    uint16_t* bl_insn = find_ticket(region, data, size);
    if(!bl_insn)
        return 0;
    
    int found = 0;
    uint16_t* pop = NULL;
    uint16_t* current_insn = bl_insn;
    while((uintptr_t)current_insn < (uintptr_t)(data + size))
    {
        if((*(uint16_t*)current_insn == 0xBDF0) && !insn_is_32bit(current_insn)) // find pop {r4-47, pc}, TODO
        {
            found = 1;
            pop = current_insn;
            break;
            
        }
        current_insn += insn_is_32bit(current_insn) ? 2 : 1;
    }
    if(!pop)
        return 0;
    
    found = 0;
    uint16_t* insn = NULL;
    uint16_t* pref = NULL;
    current_insn = pop;
    while((uintptr_t)current_insn < (uintptr_t)(data + size))
    {
        if(insn_is_b_conditional(current_insn) || insn_is_b_unconditional(current_insn))
        {
            found = 1;
            insn = current_insn;
            insn += insn_is_32bit(insn) ? 2 : 1;
            break;
            
        }
        if(insn_is_32bit(current_insn) && (*(uint32_t*)current_insn == 0x30fff04f))
        {
            found = 1;
            insn = current_insn;
            break;
        }
        pref = current_insn;
        pref -= 2;
        if(!insn_is_32bit(pref))
            pref += 1;
        current_insn = pref;
    }
    if(!insn)
        return 0;
    
    return (uintptr_t)insn - (uintptr_t)data;
}

uint32_t find_boot_partition(uint32_t region, uint8_t* data, size_t size)
{
    uint16_t* ref = find_ldr_xref_with_str(region, data, size, "boot-partition");
    if(!ref)
        return 0;
    
    uint16_t* insn = NULL;
    uint16_t* current_insn = ref;
    int i = 0;
    while((uintptr_t)current_insn < (uintptr_t)(data + size) && i < 0x100)
    {
        
        if(*(uint32_t*)current_insn == 0xbf002000)
        {
            // already patched
            break;
        }
        
        if(insn_is_bl(current_insn))
        {
            insn = current_insn;
            break;
        }
        
        i += insn_is_32bit(current_insn) ? 4 : 2;
        current_insn += insn_is_32bit(current_insn) ? 2 : 1;
    }
    if(!insn)
        return 0;
    
    return (uintptr_t)insn - (uintptr_t)data;
}

uint32_t find_boot_ramdisk(uint32_t region, uint8_t* data, size_t size)
{
    uint16_t* ref = find_ldr_xref_with_str(region, data, size, "boot-ramdisk");
    if(!ref)
        return 0;
    
    uint16_t* insn = NULL;
    uint16_t* current_insn = ref;
    
    current_insn += insn_is_32bit(current_insn) ? 2 : 1;
    
    if(!insn_is_bl(current_insn))
        return 0;
    
    insn = current_insn;
    
    return (uintptr_t)insn - (uintptr_t)data;
}

__unused uint32_t find_release_env_set_whitelist(uint32_t region, uint8_t* data, size_t size)
{
    int i = 0;
    
    uint8_t* str = NULL;
    uint32_t search[5];
    
    __unused static const char * const release_env_set_whitelist[] = {
        "auto-boot",
        "boot-args",
        "debug-uarts",
        "pwr-path",
        NULL
    };
    
    for (i = 0; NULL != release_env_set_whitelist[i]; i++) {
        str = memmem(data, size, release_env_set_whitelist[i], strlen(release_env_set_whitelist[i]));
        if(!str)
            return 0;
        
        search[i] = (uint32_t)(region + (uintptr_t)str - (uintptr_t)data);
    }
    
    search[4] = 0; // NULL
    
    uint8_t* ref = memmem(data, size, search, 4*5);
    if(!ref)
        return 0;
    
    return (uintptr_t)ref - (uintptr_t)data;
}


__unused uint32_t find_whitelist(uint32_t region, uint8_t* data, size_t size)
{
    int i = 0;
    
    uint8_t* str = NULL;
    uint32_t search[13];
    
    __unused static const char * const whitelist[] = {
        "auto-boot",
        "backlight-level",
        "boot-command",
        "com.apple.System.boot-nonce",
        "debug-uarts",
        "device-material",
        "display-rotation",
        "idle-off",
        "is-tethered",
        "darkboot",
        "ota-breadcrumbs",
        "pwr-path",
        NULL
    };
    
    for (i = 0; NULL != whitelist[i]; i++) {
        str = memmem(data, size, whitelist[i], strlen(whitelist[i]));
        if(!str)
            return 0;
        
        search[i] = (uint32_t)(region + (uintptr_t)str - (uintptr_t)data);
    }
    
    search[12] = 0; // NULL
    
    uint8_t* ref = memmem(data, size, search, 4*13);
    if(!ref)
        return 0;
    
    return (uintptr_t)ref - (uintptr_t)data;
}

uint32_t find_sys_setup_default_environment(uint32_t region, uint8_t* data, size_t size)
{
    uint16_t* ref = find_ldr_xref_with_str(region, data, size, "/System/Library/Caches/com.apple.kernelcaches/kernelcache");
    if(!ref)
        return 0;
    
    uint16_t* insn = NULL;
    uint16_t* pref = NULL;
    uint16_t* current_insn = ref;
    int i = 0;
    while((uintptr_t)current_insn < (uintptr_t)(data + size) && i < 0x100)
    {
        
        if(*(uint32_t*)current_insn == 0xbf00bf00)
        {
            // already patched
            break;
        }
        
        if(insn_is_bl(current_insn))
        {
            insn = current_insn;
            break;
        }
        
        
        pref = current_insn;
        pref -= 2;
        i += 4;
        if(!insn_is_32bit(pref)) {
            pref += 1;
            i -= 2;
        }
        current_insn = pref;
    }
    if(!insn)
        return 0;
    
    return (uintptr_t)insn - (uintptr_t)data;
}

uint32_t find_boot_args_xref(uint32_t region, uint8_t* data, size_t size)
{
    uint8_t* magicStr = memmem(data, size, "rd=md0 nand-enable-reformat=1 -progress", sizeof("rd=md0 nand-enable-reformat=1 -progress"));
    if(!magicStr)
        return 0;
    
    uint32_t search[1];
    search[0] = (uint32_t)(region + (uintptr_t)magicStr - (uintptr_t)data);
    
    uint8_t* ref = memmem(data, size, search, 4);
    if(!ref)
        return 0;
    
    return (uintptr_t)ref - (uintptr_t)data;
}

uint32_t find_boot_args_null_xref(uint32_t region, uint8_t* data, size_t size)
{
    uint16_t* bootargs_md0 = find_ldr_xref_with_str(region, data, size, "rd=md0 nand-enable-reformat=1 -progress");
    if(!bootargs_md0)
        return 0;
    
    __unused uint16_t* insn = NULL;
    __unused uint16_t* pref = NULL;
    uint16_t* current_insn = bootargs_md0;
    
    int i = 0;
    int found = 0;
    uint32_t base = 0;
    uint32_t ref = 0;
    uint32_t point = 0;
    
    current_insn += insn_is_32bit(current_insn) ? 2 : 1;
    
    while((uintptr_t)current_insn < (uintptr_t)(data + size) && i < 0x80 && !found)
    {
        if(insn_is_ldr_literal(current_insn) && insn_ldr_literal_imm(current_insn))
        {
            base = (uintptr_t)current_insn - (uintptr_t)data;
            point = base - (base & 0x3) + insn_ldr_literal_imm(current_insn) + 4;
            
            if(point < size)
            {
                ref = *(uint32_t*)(data + point);
                //printf("%x: LDR R%d, =0x%x",
                //       region + base,
                //       insn_ldr_literal_rt(current_insn),
                //       ref);
                
                if((ref&region) == region &&
                   (ref-region) < size) {
                    //printf(" ; dword_%x, \"%s\"",
                    //       region + point,
                    //       data + (ref-region));
                    if(*(uint8_t*)(data + (ref-region)) == 0x00)
                    {
                        found = 1;
                        //printf("\n");
                        break;
                    }
                }
                //printf("\n");
            }
        }
        
        i += insn_is_32bit(current_insn) ? 4 : 2;
        current_insn += insn_is_32bit(current_insn) ? 2 : 1;
    }
    
    return point;
}

uint32_t find_reliance_str(uint32_t region, uint8_t* data, size_t size)
{
    uint8_t* magicStr = memmem(data, size, "Reliance on this certificate ", sizeof("Reliance on this certificate ") - 1);
    if(!magicStr)
        return 0;
    
    return (uintptr_t)magicStr - (uintptr_t)data;
}

uint32_t find_go_cmd_handler(uint32_t region, uint8_t* data, size_t size)
{
    uint8_t* magicStr = memmem(data, size, "go", sizeof("go"));
    if(!magicStr)
        return 0;
    
    uint32_t search[1];
    search[0] = (uint32_t)(region + (uintptr_t)magicStr - (uintptr_t)data);
    
    uint8_t* ref = memmem(data, size, search, 4);
    if(!ref)
        return 0;
    
    return (uintptr_t)ref - (uintptr_t)data + 4;
}


// Helper gadget.
uint32_t find_ret0_gadget(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const uint8_t search[] = {0x00, 0x20, 0x70, 0x47};
    void* ptr = memmem(kdata, ksize, search, sizeof(search)) + 1;
    if(!ptr)
        return 0;
    
    return ((uintptr_t)ptr) - ((uintptr_t)kdata);
}

// Helper gadget.
uint32_t find_ret1_gadget(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const uint8_t search[] = {0x01, 0x20, 0x70, 0x47};
    void* ptr = memmem(kdata, ksize, search, sizeof(search)) + 1;
    if(!ptr)
        return 0;
    
    return ((uintptr_t)ptr) - ((uintptr_t)kdata);
}

// Utility function, necessary for the sandbox hook.
uint32_t find_vn_getpath(uint32_t region, uint8_t* kdata, size_t ksize)
{
    // Find a string inside the vn_getpath function
    const uint8_t search[] = {0x01, 0x20, 0xCD, 0xE9, 0x00, 0x01, 0x28, 0x46, 0x41, 0x46, 0x32, 0x46, 0x23, 0x46};
    uint16_t* fn = memmem(kdata, ksize, search, sizeof(search));
    if(!fn)
        return 0;
    
    // Find the start of the function
    uint16_t* fn_start = find_last_insn_matching(region, kdata, ksize, fn, insn_is_preamble_push);
    if(!fn_start)
        return 0;
    
    return ((uintptr_t)fn_start | 1) - ((uintptr_t)kdata);
}

// Utility function, necessary for the sandbox hook.
uint32_t find_memcmp(uint32_t region, uint8_t* kdata, size_t ksize)
{
    // Okay, search is actually the entire text of memcmp. This is in order to distinguish it from bcmp. However, memcmp is the same as bcmp if you only care about equality.
    const uint8_t search[] =
    {
        0x00, 0x23, 0x62, 0xB1, 0x91, 0xF8, 0x00, 0x90,
        0x03, 0x78, 0x4B, 0x45, 0x09, 0xD1, 0x01, 0x3A,
        0x00, 0xF1, 0x01, 0x00, 0x01, 0xF1, 0x01, 0x01,
        0x4F, 0xF0, 0x00, 0x03, 0xF2, 0xD1, 0x18, 0x46,
        0x70, 0x47, 0xA3, 0xEB, 0x09, 0x03, 0x18, 0x46,
        0x70, 0x47
    };
    
    void* ptr = memmem(kdata, ksize, search, sizeof(search)) + 1;
    if(!ptr)
        return 0;
    
    return ((uintptr_t)ptr | 1) - ((uintptr_t)kdata);
}



uint32_t find_vm_fault_enter_patch(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const struct find_search_mask search_masks[] =
    {
        {0xF800, 0x6800}, // LDR R2, [Ry,#X]
        {0xF8FF, 0x2800}, // CMP Rx, #0
        {0xFF00, 0xD100}, // BNE x
        {0xFBF0, 0xF010}, // TST.W Rx, #0x200000
        {0x0F00, 0x0F00},
        {0xFF00, 0xD100}, // BNE x
        {0xFFF0, 0xF400}, // AND.W Rx, Ry, #0x100000
        {0xF0FF, 0x1080}
    };
    
    uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!insn)
        return 0;
    
    return ((uintptr_t)insn) - ((uintptr_t)kdata);
}

// Change TST.W instruction here with NOP, CMP R0, R0 (0x4280BF00)
uint32_t find_vm_map_enter_patch(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const struct find_search_mask search_masks[] =
    {
        {0xFFF0, 0xF010}, // TST.W Rz, #4
        {0xFFFF, 0x0F04},
        {0xFF78, 0x4600}, // MOV Rx, R0 (?)
        {0xFFF0, 0xBF10}, // IT NE (?)
        {0xFFF0, 0xF020}, // BICNE.W         Rk, Rk, #4
        {0xF0FF, 0x0004}
    };
    
    uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!insn)
        return 0;
    
    insn += 4;
    return ((uintptr_t)insn) - ((uintptr_t)kdata);
}

// NOP out the BICNE.W instruction with 4 here.
uint32_t find_vm_map_protect_patch(uint32_t region, uint8_t* kdata, size_t ksize)
{
    
    const struct find_search_mask search_masks_a6[] =
    {
        {0xFBF0, 0xF010}, // TST.W   Rx, #0x20000000
        {0x8F00, 0x0F00},
        {0xFFC0, 0x6840}, // LDR     Rz, [Ry,#4]
        {0xFFF0, 0xF000}, // AND.W   Ry, Rk, #6
        {0xF0FF, 0x0006},
        {0xFFC0, 0x68C0}, // LDR     Rs, [Ry,#0xC]
        {0xFF00, 0x4600}, // MOV     Rx, Ry (?)
        {0xFFF0, 0xBF00}, // IT      EQ (?)
        {0xFFF0, 0xF020}, // BICNE.W Rk, Rk, #4
        {0xF0FF, 0x0004}
        //{0xF8FF, 0x2806}, // CMP     Ry, #6
        //{0xFFF0, 0xBF00}, // IT      EQ
    };
    
    const struct find_search_mask search_masks_a5[] =
    {
        {0xFBF0, 0xF010}, // TST.W   Rx, #0x20000000
        {0x8F00, 0x0F00},
        {0xFFC0, 0x6840}, // LDR     Rz, [Ry,#4]
        {0xFFC0, 0x68C0}, // LDR     Rs, [Ry,#0xC]
        {0xFF00, 0x4600}, // MOV     Rx, Ry (?)
        {0xFFF0, 0xF000}, // AND.W   Ry, Rk, #6
        {0xF0FF, 0x0006},
        {0xFFF0, 0xBF00}, // IT      EQ (?)
        {0xFFF0, 0xF020}, // BICNE.W Rk, Rk, #4
        {0xF0FF, 0x0004}
        //{0xF8FF, 0x2806}, // CMP     Ry, #6
        //{0xFFF0, 0xBF00}, // IT      EQ
    };
    
    uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks_a6) / sizeof(*search_masks_a6), search_masks_a6);
    if(!insn)
        insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks_a5) / sizeof(*search_masks_a6), search_masks_a5);
    
    if(!insn)
        return 0;
    
    insn += 8;
    
    return ((uintptr_t)insn) - ((uintptr_t)kdata);
}

uint32_t find_mount(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const struct find_search_mask search_masks[] =
    {
        {0xFF00, 0xD100}, // bne    loc_x
        {0xF0FF, 0x2001}, // movs   rx, #0x1
        {0xFF00, 0xE000}, // b      loc_x
        {0xF0FF, 0x2001}, // movs   rx, #0x1
        {0xFF00, 0xE000}, // b      loc_x
        {0xFFF0, 0xF440}, // orr    fp, fp, #0x10000
        {0xF0FF, 0x3080}
    };
    
    uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!insn)
        return 0;
    
    return ((uintptr_t)insn) - ((uintptr_t)kdata) + 1;
}

uint32_t find_mount_90(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const struct find_search_mask search_masks[] =
    {
        {0xFFF0, 0xF420},
        {0xF0FF, 0x3080},
        {0xFFF0, 0xF010},
        {0xFFFF, 0x0F20},
        {0xFFFF, 0xBF08},
        {0xFFF0, 0xF440},
        {0xF0FF, 0x3080},
        {0xFFF0, 0xF010},
        {0xFFFF, 0x0F01}
    };
    
    uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!insn)
        return 0;
    
    insn += 9;
    
    return ((uintptr_t)insn) - ((uintptr_t)kdata) + 1;
}

uint32_t find_csops(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const struct find_search_mask search_masks[] =
    {
        {0xFFF0, 0xF100},
        {0x0000, 0x0000},
        {0xFF80, 0x4600},
        {0xFC00, 0xF400},
        {0x0000, 0x0000},
        {0xFFF0, 0xF890},
        {0x0000, 0x0000},
        {0xFFF0, 0xF010},
        {0xFFFF, 0x0F01},
        {0xF800, 0xD000},
    };
    
    uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!insn)
        return 0;
    
    insn += 9;
    
    return ((uintptr_t)insn) - ((uintptr_t)kdata);
}

// modify the cs flags
uint32_t find_amfi_execve_ret(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const struct find_search_mask search_masks[] =
    {
        // :: AMFI.kext
        {0xFFFF, 0xF8DA},   // ldr.w rx, [sl]
        {0x0FFF, 0x0000},
        {0xFFF0, 0xF010},   // tst.w rx, #8
        {0xFFFF, 0x0F08},
        {0xFFF0, 0xBF10},   // it    ne
        {0xFFF0, 0xF440},   // orr   rx, rx, #0x800000
        {0xF0FF, 0x0000},
        {0xFFFF, 0xF8CA},   // str.w rx, [sl]
        {0x0FFF, 0x0000},
        {0xF8FF, 0x2000},   // movs  rk, #0
        {0xFF80, 0xB000},   // add   sp, #x         <- replace @ jump to shellcode
        {0xFFFF, 0xE8BD},   // pop.w {r8, sl, fp}
        {0xFFFF, 0x0D00},
        {0xFFFF, 0xBDF0}    // pop   {r4, r5, r6, r7, pc}
    };
    
    uint16_t* fn_start = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    
    if(!fn_start) {
        return 0;
    }
    
    return ((uintptr_t)fn_start) - ((uintptr_t)kdata) + 20;
}

uint32_t find_amfi_cs_enforcement_got(uint32_t region, uint8_t* kdata, size_t ksize)
{
    uint8_t* errString = memmem(kdata, ksize, "failed getting entitlements", sizeof("failed getting entitlements"));
    if(!errString)
        return 0;
    
    uint16_t* ref = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)errString - (uintptr_t)kdata);
    if(!ref)
        return 0;
    
    // find 'BL _cs_enforcement.stub'
    uint16_t* bl = NULL;
    uint16_t* current_instruction = ref;
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_bl(current_instruction))
        {
            bl = current_instruction;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    if(!bl)
        return 0;
    
    // get address of GOT stub
    uint32_t imm32 = insn_bl_imm32(bl);
    uint32_t target = ((uintptr_t)bl - (uintptr_t)kdata) + 4 + imm32;
    if(target > ksize)
        return 0;
    
    // Find the first PC-relative reference in this function.
    int found = 0;
    int rd;
    current_instruction = (uint16_t*)(kdata + target);
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_add_reg(current_instruction) && insn_add_reg_rm(current_instruction) == 15)
        {
            found = 1;
            rd = insn_add_reg_rd(current_instruction);
            current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    
    if(!found)
        return 0;
    
    return find_pc_rel_value(region, kdata, ksize, current_instruction, rd);
}

uint32_t find_amfi_PE_i_can_has_debugger_got(uint32_t region, uint8_t* kdata, size_t ksize)
{
    uint8_t* errString = memmem(kdata, ksize, "failed getting entitlements", sizeof("failed getting entitlements"));
    if(!errString)
        return 0;
    
    uint16_t* ref = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)errString - (uintptr_t)kdata);
    if(!ref)
        return 0;
    
    // find 'BL _cs_enforcement.stub'
    uint16_t* bl = NULL;
    uint16_t* current_instruction = ref;
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_bl(current_instruction))
        {
            bl = current_instruction;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    if(!bl)
        return 0;
    
    // push 1-inst
    current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    
    // find 'BL _PE_i_can_has_debugger.stub'
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_bl(current_instruction))
        {
            bl = current_instruction;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    if(!bl)
        return 0;
    
    // get address of GOT stub
    uint32_t imm32 = insn_bl_imm32(bl);
    uint32_t target = ((uintptr_t)bl - (uintptr_t)kdata) + 4 + imm32;
    if(target > ksize)
        return 0;
    
    // Find the first PC-relative reference in this function.
    int found = 0;
    int rd;
    current_instruction = (uint16_t*)(kdata + target);
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_add_reg(current_instruction) && insn_add_reg_rm(current_instruction) == 15)
        {
            found = 1;
            rd = insn_add_reg_rd(current_instruction);
            current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    
    if(!found)
        return 0;
    
    return find_pc_rel_value(region, kdata, ksize, current_instruction, rd);
}

uint32_t find_PE_i_can_has_kernel_configuration_got(uint32_t region, uint8_t* kdata, size_t ksize)
{
    uint8_t* magicStr = memmem(kdata, ksize, "_mapForIO", sizeof("_mapForIO"));
    if(!magicStr)
        return 0;
    
    uint16_t* ref = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)magicStr - (uintptr_t)kdata);
    if(!ref)
        return 0;
    
    // find 'BL _IOLog.stub'
    uint16_t* bl = NULL;
    uint16_t* current_instruction = ref;
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_bl(current_instruction))
        {
            bl = current_instruction;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    if(!bl)
        return 0;
    
    // push 1-inst
    current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    
    // find 'BL _PE_i_can_has_kernel_configuration.stub' (9.3-9.3.1: _PE_i_can_has_debugger)
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_bl(current_instruction))
        {
            bl = current_instruction;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    if(!bl)
        return 0;
    
    // get address of GOT stub
    uint32_t imm32 = insn_bl_imm32(bl);
    uint32_t target = ((uintptr_t)bl - (uintptr_t)kdata) + 4 + imm32;
    if(target > ksize)
        return 0;
    
    // Find the first PC-relative reference in this function.
    int found = 0;
    int rd;
    current_instruction = (uint16_t*)(kdata + target);
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_add_reg(current_instruction) && insn_add_reg_rm(current_instruction) == 15)
        {
            found = 1;
            rd = insn_add_reg_rd(current_instruction);
            current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    
    if(!found)
        return 0;
    
    return find_pc_rel_value(region, kdata, ksize, current_instruction, rd);
}

uint32_t find_lwvm_jump(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const struct find_search_mask search_masks[] =
    {
        {0xF800, 0x6800},  // LDR   Rx, [Ry, #z] <-
        {0xFF00, 0x4400},  // ADD   Rx, Ry
        {0xF800, 0x7800}, //  LDRB  Rx, [Ry, #z]
        {0xFFF0, 0xF010}, //  TST.W Rx, #0x1
        {0xFFFF, 0x0F01},
        {0xFF00, 0xD000}, //  BEQ.N
    };
    
    uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!insn)
        return 0;
    
    return ((uintptr_t)insn) + 0 - ((uintptr_t)kdata) + 1;
}

// NOP out the conditional branch here (prevent kIOReturnLockedWrite error).
uint32_t find_mapForIO(uint32_t region, uint8_t* kdata, size_t ksize)
{
    
    const struct find_search_mask search_masks[] =
    {
        {0xFFF0, 0xF8D0},
        {0x0000, 0x0000},
        {0xFFF0, 0xF890},
        {0x0000, 0x0000},
        {0xFF00, 0x4800},
        {0xFFFF, 0x2900},
        {0xFBC0, 0xF040},
        {0xD000, 0x8000}
    };
    
    uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!insn)
        return 0;
    
    insn += 6;
    
    return ((uintptr_t)insn) - ((uintptr_t)kdata);
}

uint32_t find_sandbox_mac_policy_ops(uint32_t region, uint8_t* kdata, size_t ksize)
{
    uint8_t* sbStr = memmem(kdata, ksize, "Seatbelt sandbox policy", sizeof("Seatbelt sandbox policy"));
    if(!sbStr)
        return 0;
    uint32_t fullname = (uint32_t)sbStr - (uintptr_t)kdata;
    
    uint32_t search[1];
    search[0] = fullname+region;
    
    uint8_t* findPtr = memmem(kdata, ksize, &search, 4);
    if(!findPtr)
        return 0;
    uint32_t mpc_top = (uint32_t)findPtr - (uintptr_t)kdata - 4;
    uint32_t ops_off = mpc_top += 0x10;
    uint32_t ops = *(uint32_t*)(kdata + ops_off) - region;
    return ops;
}

uint32_t find_sb_PE_i_can_has_debugger_got(uint32_t region, uint8_t* kdata, size_t ksize, uint32_t ops)
{
    //ops = 0;
    
    uint8_t* magicStr = memmem(kdata, ksize, "amfi_copy_seatbelt_profile_names() failed", sizeof("amfi_copy_seatbelt_profile_names() failed"));
    if(!magicStr)
        return 0;
    
    uint16_t* ref = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)magicStr - (uintptr_t)kdata);
    if(!ref)
        return 0;
    
    // find 'BL _strlen.stub'
    uint16_t* bl = NULL;
    uint16_t* current_instruction = ref;
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_bl(current_instruction))
        {
            bl = current_instruction;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    if(!bl)
        return 0;
    
    // push 1-inst
    current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    
    // find 'BL _PE_i_can_has_debugger.stub'
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_bl(current_instruction))
        {
            bl = current_instruction;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    if(!bl)
        return 0;
    
    // get address of GOT stub
    uint32_t imm32 = insn_bl_imm32(bl);
    uint32_t target = ((uintptr_t)bl - (uintptr_t)kdata) + 4 + imm32;
    if(target > ksize)
        return 0;
    
    // Find the first PC-relative reference in this function.
    int found = 0;
    int rd;
    current_instruction = (uint16_t*)(kdata + target);
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_add_reg(current_instruction) && insn_add_reg_rm(current_instruction) == 15)
        {
            found = 1;
            rd = insn_add_reg_rd(current_instruction);
            current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    
    if(!found)
        return 0;
    
    return find_pc_rel_value(region, kdata, ksize, current_instruction, rd);
}

uint32_t find_tfp0_patch(uint32_t region, uint8_t* kdata, size_t ksize)
{
    // Find the beginning of task_for_pid function
    const struct find_search_mask search_masks[] =
    {
        {0xF8FF, 0x9003}, // str rx, [sp, #0xc]
        {0xF8FF, 0x9002}, // str rx, [sp, #0x8]
        {0xF800, 0x2800}, // cmp rx, #0
        {0xFBC0, 0xF000}, // beq  <-- NOP
        {0xD000, 0x8000},
        {0xF800, 0xF000}, // bl _port_name_to_task
        {0xF800, 0xF800},
        {0xF8FF, 0x9003}, // str rx, [sp, #0xc]
        {0xF800, 0x2800}, // cmp rx, #0
        {0xFBC0, 0xF000}, // beq
        {0xD000, 0x8000}
    };
    
    const struct find_search_mask search_masks_A5[] =
    {
        {0xF8FF, 0x9003}, // str rx, [sp, #0xc]
        {0xF800, 0x2800}, // cmp rx, #0         // why?!
        {0xF8FF, 0x9002}, // str rx, [sp, #0x8]
        {0xFBC0, 0xF000}, // beq  <-- NOP
        {0xD000, 0x8000},
        {0xF800, 0xF000}, // bl _port_name_to_task
        {0xF800, 0xF800},
        {0xF8FF, 0x9003}, // str rx, [sp, #0xc]
        {0xF800, 0x2800}, // cmp rx, #0
        {0xFBC0, 0xF000}, // beq
        {0xD000, 0x8000}
    };
    
    uint16_t* fn_start = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    
    if(!fn_start) {
        fn_start = find_with_search_mask(region, kdata, ksize, sizeof(search_masks_A5) / sizeof(*search_masks_A5), search_masks_A5);
        if(!fn_start) {
            return 0;
        }
    }
    
    return ((uintptr_t)fn_start) + 6 - ((uintptr_t)kdata);
}

int find_xnu_major_version(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const char* xnu_str = "root:xnu-";
    uint8_t* magicStr = memmem(kdata, ksize, xnu_str, strlen(xnu_str));
    if(!magicStr)
        return 0;

    magicStr += strlen(xnu_str);
    
    char str[32];
    memset(str, 0x0, 32);
    int i = 0;
    while((*(uint8_t*)magicStr &~ 0x0F) == 0x30) {
        memcpy(str+i, magicStr, 1);
        magicStr++;
        i++;
    }
    
    return strtol(str, NULL, 0);
}

int find_xnu_minor_version(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const char* xnu_str = "root:xnu-";
    uint8_t* magicStr = memmem(kdata, ksize, xnu_str, strlen(xnu_str));
    if(!magicStr)
        return 0;
    
    magicStr += strlen(xnu_str);
    
    while(*(uint8_t*)magicStr != 0x2E)
    {
        magicStr++;
    }
    
    magicStr++;
    
    char str[32];
    memset(str, 0x0, 32);
    int i = 0;
    while((*(uint8_t*)magicStr &~ 0x0F) == 0x30) {
        memcpy(str+i, magicStr, 1);
        magicStr++;
        i++;
    }
    
    return strtol(str, NULL, 0);
}

// ios 6.x
// NOP out the conditional branch here.
uint32_t find_vm_map_enter_patch_ios6(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const struct find_search_mask search_masks[] =
    {
        {0xFFF0, 0xF000}, // AND Rx, Ry, #6
        {0xF0FF, 0x0006},
        {0xF8FF, 0x2806}  // CMP Rx, #6
    };
    
    uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!insn)
        return 0;
    
    insn += 3;
    
    return ((uintptr_t)insn) - ((uintptr_t)kdata);
}

// Change the conditional branch here to an unconditional branch.
uint32_t find_vm_map_protect_patch_ios6(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const uint8_t search[] = {0x08, 0xBF, 0x10, 0xF0, 0x80, 0x4F};
    uint16_t* insn = memmem(kdata, ksize, search, sizeof(search));
    if(!insn)
        return 0;
    
    insn += 3;
    
    return ((uintptr_t)insn) - ((uintptr_t)kdata);
}

// Change the conditional branch here to an unconditional branch.
uint32_t find_tfp0_patch_ios6(uint32_t region, uint8_t* kdata, size_t ksize)
{
    // Find the task_for_pid function
    const uint8_t search[] = {0x02, 0x46, 0x30, 0x46, 0x21, 0x46, 0x53, 0x46};
    uint16_t* fn = memmem(kdata, ksize, search, sizeof(search));
    if(!fn)
        return 0;
    
    // Find the beginning of it
    uint16_t* fn_start = find_last_insn_matching(region, kdata, ksize, fn, insn_is_preamble_push);
    if(!fn_start)
        return 0;
    
    // Find where something is checked to be 0 (the PID check)
    int found = 0;
    uint16_t* current_instruction = fn_start;
    while((uintptr_t)current_instruction < (uintptr_t)fn)
    {
        if(insn_is_cmp_imm(current_instruction) && insn_cmp_imm_imm(current_instruction) == 0)
        {
            found = 1;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    
    if(!found)
        return 0;
    
    // Find the next conditional branch
    found = 0;
    while((uintptr_t)current_instruction < (uintptr_t)fn)
    {
        // The unconditional branch is to detect an already patched function and still return the right address.
        if(insn_is_b_conditional(current_instruction) || insn_is_b_unconditional(current_instruction))
        {
            found = 1;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    
    if(!found)
        return 0;
    
    return ((uintptr_t)current_instruction) - ((uintptr_t)kdata);
}

uint32_t find_amfi_PE_i_can_has_debugger_got_ios6(uint32_t region, uint8_t* kdata, size_t ksize)
{
    uint8_t* errString = memmem(kdata, ksize, "amfi_unrestrict_task_for_pid", sizeof("amfi_unrestrict_task_for_pid"));
    if(!errString)
        return 0;
    
    uint16_t* ref = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)errString - (uintptr_t)kdata);
    if(!ref)
        return 0;
    
    // find 'BL _vn_getpath'
    uint16_t* insn = NULL;
    uint16_t* pref = NULL;
    uint16_t* current_insn = ref;
    int i = 0;
    while((uintptr_t)current_insn < (uintptr_t)(kdata + ksize) && i < 0x100)
    {
        
        if(*(uint32_t*)current_insn == 0xbf00bf00)
        {
            // already patched
            break;
        }
        
        if(insn_is_bl(current_insn))
        {
            insn = current_insn;
            break;
        }
        
        
        pref = current_insn;
        pref -= 2;
        i += 4;
        if(!insn_is_32bit(pref)) {
            pref += 1;
            i -= 2;
        }
        current_insn = pref;
    }
    if(!insn)
        return 0;
    
    pref = current_insn;
    pref -= 2;
    i += 4;
    if(!insn_is_32bit(pref)) {
        pref += 1;
        i -= 2;
    }
    current_insn = pref;
    
    while((uintptr_t)current_insn < (uintptr_t)(kdata + ksize) && i < 0x100)
    {
        
        if(*(uint32_t*)current_insn == 0xbf00bf00)
        {
            // already patched
            break;
        }
        
        if(insn_is_bl(current_insn))
        {
            insn = current_insn;
            break;
        }
        
        
        pref = current_insn;
        pref -= 2;
        i += 4;
        if(!insn_is_32bit(pref)) {
            pref += 1;
            i -= 2;
        }
        current_insn = pref;
    }
    if(!insn)
        return 0;
    
    // get address of GOT stub
    uint32_t imm32 = insn_bl_imm32(insn);
    uint32_t target = ((uintptr_t)insn - (uintptr_t)kdata) + 4 + imm32;
    if(target > ksize)
        return 0;
    
    // Find the first PC-relative reference in this function.
    int found = 0;
    int rd;
    current_insn = (uint16_t*)(kdata + target);
    while((uintptr_t)current_insn < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_add_reg(current_insn) && insn_add_reg_rm(current_insn) == 15)
        {
            found = 1;
            rd = insn_add_reg_rd(current_insn);
            current_insn += insn_is_32bit(current_insn) ? 2 : 1;
            break;
        }
        
        current_insn += insn_is_32bit(current_insn) ? 2 : 1;
    }
    
    if(!found)
        return 0;
    
    return find_pc_rel_value(region, kdata, ksize, current_insn, rd);
}

uint32_t find_sb_PE_i_can_has_debugger_got_ios6(uint32_t region, uint8_t* kdata, size_t ksize, uint32_t ops)
{
    //ops = 0;
    
    uint8_t* magicStr = memmem(kdata, ksize, "smalloc() failed", sizeof("smalloc() failed"));
    if(!magicStr)
        return 0;
    
    uint16_t* ref = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)magicStr - (uintptr_t)kdata);
    if(!ref)
        return 0;
    
    // find 'BL _strlen.stub'
    uint16_t* bl = NULL;
    uint16_t* current_instruction = ref;
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_bl(current_instruction))
        {
            bl = current_instruction;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    if(!bl)
        return 0;
    
    // push 1-inst
    current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    
    // find 'BL _PE_i_can_has_debugger.stub'
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_bl(current_instruction))
        {
            bl = current_instruction;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    if(!bl)
        return 0;
    
    // get address of GOT stub
    uint32_t imm32 = insn_bl_imm32(bl);
    uint32_t target = ((uintptr_t)bl - (uintptr_t)kdata) + 4 + imm32;
    if(target > ksize)
        return 0;
    
    // Find the first PC-relative reference in this function.
    int found = 0;
    int rd;
    current_instruction = (uint16_t*)(kdata + target);
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_add_reg(current_instruction) && insn_add_reg_rm(current_instruction) == 15)
        {
            found = 1;
            rd = insn_add_reg_rd(current_instruction);
            current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    
    if(!found)
        return 0;
    
    return find_pc_rel_value(region, kdata, ksize, current_instruction, rd);
}

uint32_t find_sb_patch(uint32_t region, uint8_t* kdata, size_t ksize)
{
    // Find location of the "control_name" string.
    uint8_t* control_name = memmem(kdata, ksize, "control_name", sizeof("control_name"));
    if(!control_name)
        return 0;
    
    // Find a reference to the "control_name" string.
    uint16_t* ref = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)control_name - (uintptr_t)kdata);
    if(!ref)
        return 0;
    
    // Find the start of the function referencing "control_name"
    uint16_t* fn_start = ref;
    while(1)
    {
        fn_start = find_last_insn_matching(region, kdata, ksize, fn_start, insn_is_push);
        if(!fn_start)
            return 0;
        
        uint16_t registers = insn_push_registers(fn_start);
        // We match PUSH {R0, R1} as well to detect an already patched version.
        if((registers & (1 << 14)) != 0 || (registers & (1 << 0 | 1 << 1)) == (1 << 0 | 1 << 1))
            break;
    }
    
    return ((uintptr_t)fn_start) - ((uintptr_t)kdata);
}

uint32_t find_vm_fault_enter_patch_84(uint32_t region, uint8_t* kdata, size_t ksize)
{
    
    const struct find_search_mask search_masks_a5[] =
    {
        // A5(x&rA) 8.4.1
        {0xF0F0, 0xF000}, // AND.W Rx, Ry, #0x40
        {0xF0FF, 0x0040}, //
        {0xFFF0, 0xF8D0}, // ldr.w x, [Ry, #z]
        {0x0000, 0x0000},
        {0xFFF0, 0xF8D0}, // ldr.w x, [Ry, #z]
        {0x0000, 0x0000},
        {0xFBF0, 0xF010}, // TST.W Rx, #0x200000
        {0x0F00, 0x0F00},
        {0xFF00, 0xD100}, // BNE x              <- NOP
        {0xF800, 0x6800}, // LDR R2, [Ry,#X]    <- movs r2, #1
        
    };
    
    uint16_t* insn_a5 = find_with_search_mask(region, kdata, ksize, sizeof(search_masks_a5) / sizeof(*search_masks_a5), search_masks_a5);
    if (insn_a5) {
        return (uintptr_t)insn_a5 - (uintptr_t)kdata +16;
    }
    
    
    uint16_t* ref = NULL;
    
    const struct find_search_mask search_masks[] = {
        {0xF0F0, 0xF000}, // AND.W Rx, Ry, #0x40
        {0xF0FF, 0x0040}, //
        {0xFBF0, 0xF010}, // TST.W Rx, #0x200000
        {0x0F00, 0x0F00},
    };
    
    uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if (!insn) {
        return 0;
    }
    
    // find 'Bxx loc_xxx'
    uint16_t* bne = NULL;
    
    uint16_t* current_instruction = insn;
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_b_conditional(current_instruction))
        {
            bne = current_instruction;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    if(!bne)
        return 0;
    
    ref = current_instruction; // save current insn
    
    
    current_instruction += insn_is_32bit(current_instruction) ? 2 : 1; // push
    
    // find next 'Bxx loc_xxx'
    bne = NULL;
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_b_conditional(current_instruction))
        {
            bne = current_instruction;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    if(!bne)
        return 0;
    current_instruction -= insn_is_32bit(current_instruction) ? 2 : 1; // back
    
    // checkpoint
    if(!insn_is_cmp_imm(current_instruction))
        return 0;
    
    return (uintptr_t)ref - (uintptr_t)kdata;
}

// Change TST.W instruction here with NOP, CMP R0, R0 (0x4280BF00)
uint32_t find_vm_map_enter_patch_84(uint32_t region, uint8_t* kdata, size_t ksize)
{
    
    const struct find_search_mask search_masks_84[] =
    {
        {0xFFF0, 0xF000}, // AND.W Rx, Ry, #2
        {0xF0FF, 0x0002},
        {0xFFF0, 0xF010}, // TST.W Rz, #2
        {0xFFFF, 0x0F02},
        {0xFF00, 0xD000}, // BEQ   loc_xxx
        {0xF8FF, 0x2000}, // MOVS  Rk, #0
        {0xFFF0, 0xF010}, // TST.W Rz, #4
        {0xFFFF, 0x0F04}
    };
    
    const struct find_search_mask search_masks[] =
    {
        {0xFBE0, 0xF000},
        {0x8000, 0x0000},
        {0xFFF0, 0xF010},
        {0xFFFF, 0x0F02},
        {0xFF00, 0xD000},
        {0xF8FF, 0x2000},
        {0xFFF0, 0xF010},
        {0xFFFF, 0x0F04}
    };
    
    uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks_84) / sizeof(*search_masks_84), search_masks_84);
    if(!insn) {
        insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
        if(!insn) {
            return 0;
        }
    }
    
    insn += 2;
    
    return ((uintptr_t)insn) - ((uintptr_t)kdata);
}

// NOP out the BICNE.W instruction with 4 here.
uint32_t find_vm_map_protect_patch_84(uint32_t region, uint8_t* kdata, size_t ksize)
{
    
    const struct find_search_mask search_masks_84[] =
    {
        {0xFBF0, 0xF010}, // TST.W Rx, #0x20000000
        {0x8F00, 0x0F00},
        {0xFBFF, 0xF04F}, // MOV.W Rx, #0
        {0x8000, 0x0000},
        {0xFFF0, 0xBF00}, // IT EQ
        {0xF8FF, 0x2001}, // MOVEQ Rx, #1
        {0xFFC0, 0x6840}, // LDR             Rz, [Ry,#4]
        {0xFFC0, 0x68C0}, // LDR             Rs, [Ry,#0xC]
        {0xFFF0, 0xF000}, // AND.W           Ry, Rk, #6
        {0xF0FF, 0x0006},
        {0xF8FF, 0x2806}, // CMP             Ry, #6
        {0xFBFF, 0xF04F}, // MOV.W           Ry, #0
        {0x8000, 0x0000},
        {0xFFF0, 0xBF00}, // IT EQ (?)
        {0xF8FF, 0x2001}, // MOVEQ           Ry, #1
        {0xFFC0, 0x4200}, // TST             Ry, Rx
        {0xFFF0, 0xBF10}, // IT NE (?)
        {0xFFF0, 0xF020}, // BICNE.W         Rk, Rk, #4
        {0xF0FF, 0x0004}
    };
    
    const struct find_search_mask search_masks[] =
    {
        {0xFBF0, 0xF010},
        {0x8F00, 0x0F00},
        {0xFBFF, 0xF04F},
        {0x8000, 0x0000},
        {0xFFF0, 0xF000},
        {0xF0FF, 0x0006},
        {0xFFF0, 0xBF00},
        {0xF8FF, 0x2001},
        {0xF8FF, 0x2806},
        {0xFBFF, 0xF04F},
        {0x8000, 0x0000},
        {0xFFF0, 0xBF00},
        {0xF8FF, 0x2001},
        {0xFFC0, 0x4200},
        {0xFFF0, 0xBF10},
        {0xFFF0, 0xF020},
        {0xF0FF, 0x0004}
    };
    
    uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks_84) / sizeof(*search_masks_84), search_masks_84);
    if(!insn) {
        insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
        if(!insn) {
            return 0;
        }
        insn += 15;
    } else {
        insn += 17;
    }
    
    return ((uintptr_t)insn) - ((uintptr_t)kdata);
}

uint32_t find_mount_84(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const struct find_search_mask search_masks[] =
    {
        {0xFFF0, 0xF420},
        {0xF0FF, 0x3080},
        {0xFFF0, 0xF010},
        {0xFFFF, 0x0F20},
        {0xFFFF, 0xBF08},
        {0xFFF0, 0xF440},
        {0xF0FF, 0x3080},
        {0xFFF0, 0xF010},
        {0xFFFF, 0x0F01}
    };
    
    uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!insn)
    return 0;
    
    insn -= 1;
    
    return ((uintptr_t)insn) - ((uintptr_t)kdata) + 1;
}

// Replace with NOP
uint32_t find_csops_84(uint32_t region, uint8_t* kdata, size_t ksize)
{
    
    const struct find_search_mask search_masks[] =
    {
        {0xFC00, 0xF400},
        {0x0000, 0x0000},
        {0xF800, 0xE000},
        {0x0000, 0x0000},
        {0xFFF0, 0xF100},
        {0x0000, 0x0000},
        {0xFF80, 0x4600},
        {0xF800, 0xF000},
        {0x0000, 0x0000},
        {0xFF80, 0x4600},
        {0xFFF0, 0xF890},
        {0x0000, 0x0000},
        {0xFFF0, 0xF010},
        {0xFFFF, 0x0F01},
        {0xFC00, 0xF000},
        {0x0000, 0x0000}
    };
    
    uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!insn) {
        return 0;
    }
    
    insn += 14;
    
    return ((uintptr_t)insn) - ((uintptr_t)kdata);
}

// Set 0x20 here. Replace
uint32_t find_csops2_84(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const struct find_search_mask search_masks[] =
    {
        {0xF800, 0x9800},
        {0xFBF0, 0xF100},
        {0x8000, 0x0000},
        {0xFFC0, 0x4600},
        {0xF800, 0xF000},
        {0xF800, 0xE800},
        {0xFFF0, 0xF8D0},
        {0x0000, 0x0000},
        {0xFAF0, 0xF040}
    };
    
    uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!insn)
    return 0;
    
    insn += 8;
    
    return ((uintptr_t)insn) - ((uintptr_t)kdata);
}

uint32_t find_amfi_cs_enforcement_got_84(uint32_t region, uint8_t* kdata, size_t ksize)
{
    uint8_t* errString = memmem(kdata, ksize, "missing or invalid entitlement hash", sizeof("missing or invalid entitlement hash"));
    if(!errString)
        return 0;
    
    uint16_t* ref = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)errString - (uintptr_t)kdata);
    if(!ref)
        return 0;
    
    // find 'BL _cs_enforcement.stub'
    uint16_t* bl = NULL;
    uint16_t* current_instruction = ref;
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_bl(current_instruction))
        {
            bl = current_instruction;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    if(!bl)
        return 0;
    
    // get address of GOT stub
    uint32_t imm32 = insn_bl_imm32(bl);
    uint32_t target = ((uintptr_t)bl - (uintptr_t)kdata) + 4 + imm32;
    if(target > ksize)
        return 0;
    
    // Find the first PC-relative reference in this function.
    int found = 0;
    int rd;
    current_instruction = (uint16_t*)(kdata + target);
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_add_reg(current_instruction) && insn_add_reg_rm(current_instruction) == 15)
        {
            found = 1;
            rd = insn_add_reg_rd(current_instruction);
            current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    
    if(!found)
        return 0;
    
    return find_pc_rel_value(region, kdata, ksize, current_instruction, rd);
}

uint32_t find_amfi_PE_i_can_has_debugger_got_84(uint32_t region, uint8_t* kdata, size_t ksize)
{
    uint8_t* errString = memmem(kdata, ksize, "amfi_unrestrict_task_for_pid", sizeof("amfi_unrestrict_task_for_pid"));
    if(!errString)
        return 0;
    
    uint16_t* ref = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)errString - (uintptr_t)kdata);
    if(!ref)
        return 0;
    
    // find 'BL sym.stub._PE_parse_boot_argn'
    uint16_t* bl = NULL;
    uint16_t* pref = NULL;
    uint16_t* current_instruction = ref;
    unsigned int i = 0;
    while(i < 0x100)
    {
        if(insn_is_bl(current_instruction))
        {
            bl = current_instruction;
            break;
        }
        pref = current_instruction;
        pref -= 2;
        i += 2;
        if(!insn_is_32bit(pref))
        pref += 1;
        i -= 1;
        current_instruction = pref;
    }
    if(!bl)
        return 0;
    
    pref = bl;
    pref -= 2;
    if(!insn_is_32bit(pref))
    pref += 1;
    current_instruction = pref;
    
    while(i < 0x100)
    {
        if(insn_is_bl(current_instruction))
        {
            bl = current_instruction;
            break;
        }
        pref = current_instruction;
        pref -= 2;
        i += 2;
        if(!insn_is_32bit(pref))
        pref += 1;
        i -= 1;
        current_instruction = pref;
    }
    if(!bl)
        return 0;
    
    // get address of GOT stub
    uint32_t imm32 = insn_bl_imm32(bl);
    uint32_t target = ((uintptr_t)bl - (uintptr_t)kdata) + 4 + imm32;
    if(target > ksize)
        return 0;
    
    // Find the first PC-relative reference in this function.
    int found = 0;
    int rd;
    current_instruction = (uint16_t*)(kdata + target);
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_add_reg(current_instruction) && insn_add_reg_rm(current_instruction) == 15)
        {
            found = 1;
            rd = insn_add_reg_rd(current_instruction);
            current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    
    if(!found)
        return 0;
    
    return find_pc_rel_value(region, kdata, ksize, current_instruction, rd);
}

uint32_t find_sb_PE_i_can_has_debugger_got_84(uint32_t region, uint8_t* kdata, size_t ksize)
{
    
    const struct find_search_mask search_masks[] =
    {
        {0xFFFF, 0xB590}, // PUSH {R4,R7,LR}
        {0xFFFF, 0x2000}, // MOVS R0, #0
        {0xFFFF, 0xAF01}, // ADD  R7, SP, #4
        {0xFFFF, 0x2400}, // MOVS R4, #0
        {0xF800, 0xF000}, // BL   i_can_has_debugger
        {0xD000, 0xD000},
        {0xFD07, 0xB100}  // CBZ  R0, loc_xxx
    };
    
    uint16_t* bl = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!bl)
        return 0;
    
    bl += 4;
    if(!insn_is_bl(bl))
        return 0;
    
    // get address of GOT stub
    uint32_t imm32 = insn_bl_imm32(bl);
    uint32_t target = ((uintptr_t)bl - (uintptr_t)kdata) + 4 + imm32;
    if(target > ksize)
    return 0;
    
    // Find the first PC-relative reference in this function.
    int found = 0;
    int rd;
    uint16_t* current_instruction = (uint16_t*)(kdata + target);
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_add_reg(current_instruction) && insn_add_reg_rm(current_instruction) == 15)
        {
            found = 1;
            rd = insn_add_reg_rd(current_instruction);
            current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    
    if(!found)
    return 0;
    
    return find_pc_rel_value(region, kdata, ksize, current_instruction, rd);
}

// NOP out the conditional branch here (prevent kIOReturnLockedWrite error).
uint32_t find_mapForIO_84(uint32_t region, uint8_t* kdata, size_t ksize)
{
    // checked on iPhone5,2 8.2 and iPhone5,1 8.4
    const struct find_search_mask search_masks_84[] =
    {
        {0xFFF0, 0xF8D0},
        {0x0000, 0x0000},
        {0xFFF0, 0xF890},
        {0x0000, 0x0000},
        {0xFF00, 0x4800},
        {0xFFFF, 0x2900},
        {0xFBC0, 0xF040},
        {0xD000, 0x8000}
    };
    
    const struct find_search_mask search_masks[] =
    {
        {0xFFF0, 0xF8D0},
        {0x0000, 0x0000},
        {0xFF00, 0x4800},
        {0xFFF0, 0xF890},
        {0x0000, 0x0000},
        {0xFFFF, 0x2900},
        {0xFBC0, 0xF040},
        {0xD000, 0x8000}
    };
    
    uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks_84) / sizeof(*search_masks_84), search_masks_84);
    if(!insn)
    insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!insn)
    return 0;
    
    insn += 6;
    
    return ((uintptr_t)insn) - ((uintptr_t)kdata);
}

// Utility function, necessary for the sandbox hook.
uint32_t find_vn_getpath_84(uint32_t region, uint8_t* kdata, size_t ksize)
{
    // Find a string inside the vn_getpath function
    const struct  find_search_mask search_masks_84[] =
    {
        {0xF8FF, 0x2001},
        {0xFFFF, 0xE9CD},
        {0x0000, 0x0000},
        {0xFF00, 0x4600},
        {0xFF00, 0x4600},
        {0xFF00, 0x4600},
        {0xFF00, 0x4600}
    };
    
    const struct find_search_mask search_masks[] =
    {
        {0xFF00, 0x4600},
        {0xF8FF, 0x2001},
        {0xFF00, 0x4600},
        {0xFF00, 0x4600},
        {0xFFFF, 0xE9CD},
        {0x0000, 0x0000},
        {0xFF00, 0x4600},
        {0xFF00, 0x4600}
    };
    
    uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks_84) / sizeof(*search_masks_84), search_masks_84);
    if(!insn)
    insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    
    if(!insn)
    return 0;
    
    // Find the start of the function
    uint16_t* fn_start = find_last_insn_matching(region, kdata, ksize, insn, insn_is_preamble_push);
    if(!fn_start)
    return 0;
    
    return ((uintptr_t)fn_start | 1) - ((uintptr_t)kdata);
}

// Utility function, necessary for the sandbox hook.
uint32_t find_memcmp_84(uint32_t region, uint8_t* kdata, size_t ksize)
{
    // Okay, search is actually the entire text of memcmp. This is in order to distinguish it from bcmp. However, memcmp is the same as bcmp if you only care about equality.
    const struct find_search_mask search_masks[] =
    {
        {0xFD00, 0xB100},
        {0xFFF0, 0xF890},
        {0x0000, 0x0000},
        {0xF800, 0x7800},
        {0xFF00, 0x4500},
        {0xFF00, 0xBF00},
        {0xFFF0, 0xEBA0},
        {0x8030, 0x0000},
        {0xFFFF, 0x4770},
        {0xF8FF, 0x3801},
        {0xFFF0, 0xF100},
        {0xF0FF, 0x0001},
        {0xFFF0, 0xF100},
        {0xF0FF, 0x0001},
        {0xFF00, 0xD100},
        {0xF8FF, 0x2000},
        {0xFFFF, 0x4770}
    };
    
    uint16_t* ptr = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!ptr)
    return 0;
    
    return ((uintptr_t)ptr | 1) - ((uintptr_t)kdata);
}

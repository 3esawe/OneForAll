#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string>
#include "inc/loader_api.h"
#include <capstone/capstone.h>
#include <cstring>
#include <iostream>
#include <map>
#include <queue>


using namespace std;

int linear_disas(Binary *bin);
int recursive_disas(Binary *bin);
void  print_ins(cs_insn *ins);
bool is_unconditional_flow(cs_insn *ins);
bool is_conditional_flow(cs_insn *ins);
uint64_t immediate_target(cs_insn *ins);
bool is_flow(cs_insn *ins);
bool is_flow_group(uint8_t g);
int find_gadgets_at_root(Section *text, uint64_t root, map<string, vector<uint64_t>> *gadgets, csh dis);
int find_gadgets(Binary *bin);

bool
is_cs_ret_ins(cs_insn *ins);


int main(int argc, char const *argv[])
{
  size_t i;
  Binary bin;
  Section *sec;
  Symbols *sym;
  string fname;
  string mode;
  mode.assign(argv[2]);
  fname.assign(argv[1]);
  if(load_binary(fname, &bin, Binary::AUTO) < 0) {
    return 1;
  }

  if(argc < 3) {
    printf("[+] Usage: %s <binary> <mode>\n", argv[0]);
    printf("[+] Mode Can be \ninfo: to get some information about symbols in the binary\nld: to linearly disassemble the binary\nrs: to recursively disassemble the binary");
    return 1;
  }



  if (mode.compare("ld") == 0){
    if (linear_disas(&bin) < -1){
        return 1;
    }
    return 0;
  }

  else if (mode.compare("info") == 0){
      printf("loaded binary '%s' %s/%s (%u bits) entry@0x%016jx\n", 
         bin.filename.c_str(), 
         bin.Bname.c_str(), bin.Aname.c_str(), 
         bin.bits, bin.entry);

  for(i = 0; i < bin.sections.size(); i++) {
    sec = &bin.sections[i];
    printf("  0x%016jx %-8ju %-20s %s\n", 
           sec->vma, sec->size, sec->name.c_str(), 
           sec->Stype == Section::CODE ? "CODE" : "DATA");
    }

  if(bin.symbols.size() > 0) {
    printf("scanned symbol tables\n");
    for(i = 0; i < bin.symbols.size(); i++) {
      sym = &bin.symbols[i];
      printf("  %-40s 0x%016jx %s\n", 
             sym->name.c_str(), sym->address, 
             (sym->Stype & Symbols::FUNC) ? "FUNC" : "");
      }
    }
  }

  else if (mode.compare("rs") == 0){
    if (recursive_disas(&bin) > 0){
        return 0;
    }
    else{
      return 1;
    }

  }
 
   else if (mode.compare("rop") == 0){
    if (find_gadgets(&bin) > 0){
        return 0;
    }
    else{
      return 1;
    }

  }


  unload_binary(&bin);

  return 0;
}

int linear_disas(Binary *bin){
  /*Capstone handler*/
  csh dis;
  cs_insn *insns;
  Section *text;
  size_t n;
  text = bin->get_text_section();

  cout << text->name  << endl; 
  cout << text->size  << endl; 
  cout << text->vma  << endl; 
  if(!text) {
    fprintf(stderr, "Nothing to disassemble\n");
    return 0;
  }

/*It’s called cs_open,  and we pass it the arch typen and the binary type whether 64 bit or 32 bit and its purpose is to open a properly
configured Capstone instance*/
  if(cs_open(CS_ARCH_X86, CS_MODE_64, &dis) != CS_ERR_OK) {
    fprintf(stderr, "Failed to open Capstone\n");
    return -1;
  }

/*typedef struct
 cs_insn {
unsigned int
 id;
uint64_t
 address;
uint16_t
 size;
uint8_t
 bytes[16];
char
 mnemonic[32];
char
 op_str[160];
cs_detail
 *
detail;
} cs_insn;
*/
  /*The first parameter to this call is dis, which is your Capstone handle.
Next, cs_disasm expects a buffer (specifically, a const uint8_t*) containing the
code to disassemble, a size_t integer indicating the number of code bytes
in the buffer, and a uint64_t indicating the virtual memory address (VMA) of
the first byte in the buffer. The code buffer and related values are all conve-
niently preloaded in the Section object representing the .text section of the
loaded binary.
*/
  n = cs_disasm(dis, text->bytes, text->size, text->vma, 0, &insns);


  if(n <= 0) {
    fprintf(stderr, "Disassembly error: %s\n", cs_strerror(cs_errno(dis)));
    return -1;
  }

  for (size_t i = 0; i < n; i ++){
    printf("0x%016x: ",insns[i].address );

    for (size_t j = 0; j < 16; j++){
      if (j < insns[i].size) printf("%02x ", insns[i].bytes[j]);
      else printf("   ");
    }
        printf("%-12s %s\n", insns[i].mnemonic, insns[i].op_str);

  }

  cs_free(insns, n);
  cs_close(&dis);

  return 0;

}



void print_ins(cs_insn *ins){
    printf("0x%016jx: ", ins->address);
  for(size_t i = 0; i < 16; i++) {
    if(i < ins->size) printf("%02x ", ins->bytes[i]);
    else printf("   ");
  }
  printf("%-12s %s\n", ins->mnemonic, ins->op_str);
}


bool is_flow_group(uint8_t g){
    return (g == CS_GRP_JUMP) || (g == CS_GRP_CALL) 
          || (g == CS_GRP_RET) || (g == CS_GRP_IRET);

}

bool is_flow(cs_insn *ins){

  for( size_t i = 0; i < ins->detail->groups_count; i++){
      if (is_flow_group(ins->detail->groups[i])){
        return true;
      }
  }
  return false;
}

bool is_unconditional_flow (cs_insn *ins){
  switch(ins->id) {
  case X86_INS_JMP:
  case X86_INS_LJMP:
  case X86_INS_RET:
  case X86_INS_RETF:
  case X86_INS_RETFQ:
    return true;
  default:
    return false;
  }
} 

/*determines whether an instruction is any kind of control flow instruction

 In particular, the ins->detail struct provided by
Capstone contains an array of “groups” to which the instruction belongs
(ins->detail->groups). 
*/
bool is_conditional_flow(cs_insn *ins){

  for(size_t i = 0; i < ins->detail->groups_count; i++) {
    if(is_flow_group(ins->detail->groups[i])) {
      return true;
    }
  }

  return false;

}


/* it’s only capable of resolving “immediate” control flow
targets: target addresses that are hardcoded in the control flow instruction.
*/

// typedef struct cs_x86_op {
//                 x86_op_type type;       // operand type
//                 union {
//                         x86_reg reg;    // register value for REG operand
//                         int64_t imm;            // immediate value for IMM operand
//                         double fp;              // floating point value for FP operand
//                         x86_op_mem mem;         // base/index/scale/disp value for MEM operand
//                 };

//                 // size of this operand (in bytes).
//                 uint8_t size;
// --
// } cs_x86_op;

/*typedef struct cs_x86 {
        // Instruction prefix, which can be up to 4 bytes.
        // A prefix byte gets value 0 when irrelevant.
        // prefix[0] indicates REP/REPNE/LOCK prefix (See X86_PREFIX_REP/REPNE/LOCK above)
        // prefix[1] indicates segment override (irrelevant for x86_64):
        // See X86_PREFIX_CS/SS/DS/ES/FS/GS above.
        // prefix[2] indicates operand-size override (X86_PREFIX_OPSIZE)
        // prefix[3] indicates address-size override (X86_PREFIX_ADDRSIZE)
--
        cs_x86_op operands[8];  // operands for this instruction.
} cs_x86;
*/

uint64_t immediate_target(cs_insn *ins){


  cs_x86_op *cs_x86;

  for (size_t i = 0; i < ins->detail->groups_count;i++){
      if(is_flow_group(ins->detail->groups[i])){
        for (size_t j = 0; j < ins->detail->x86.op_count; j++){
          cs_x86 = &ins->detail->x86.operands[j];

          if (cs_x86->type == X86_OP_IMM){
            return cs_x86->imm;
          }
        }
      }
  }
  return 0;

}

int recursive_disas(Binary *bin){
  csh dis;
  size_t n;
  cs_insn *cs_ins;
  Section *text;
  queue<uint64_t> Q;
  map<uint64_t, bool> seen;
  const uint8_t *pc;
  uint64_t addr, offset, target;

  text = bin->get_text_section();

  if(!text){
      fprintf(stderr, "Nothing to disas\n" );
      return 0;
  }

  if(cs_open(CS_ARCH_X86, CS_MODE_64, &dis) != CS_ERR_OK){
    fprintf(stderr, "Failed to open Capstone\n");
    return -1;
  }

    /*Here This
added line enables detailed disassembly mode by activating the CS_OPT_DETAIL
option.*/
  cs_option(dis, CS_OPT_DETAIL, CS_OPT_ON);


 /*This needed because we are going to use another api 
 */ 

  cs_ins = cs_malloc(dis);  
  
  if(!cs_ins){
    fprintf(stderr, "Out of memory\n");
    cs_close(&dis);
    return -1;
  }

    /*The logic here follows DFS in linear fashion so what this means is
  We add an entry point for the fucntion then mark it as visted in map structure
  */

  addr = bin->entry; // the start address of our program

  if(text->contains(addr)) Q.push(addr);
  printf("[+] Entry point is: 0x%016jx\n", addr);
    /*Explore as long as they are more starting points to explore 
  and disas code as much as possible */
  for (auto &sym : bin->symbols){
      if (sym.Stype == Symbols::FUNC && text->contains(sym.address)){
          Q.push(sym.address);
                // printf("dasdasd\n");

          printf("function symbol: 0x%016jx\n", sym.address);
      }
  }

  while(!Q.empty()){
      addr = Q.front();
      Q.pop();

      if(seen[addr]){
        printf("ignoring addr 0x%016jx (already seen)\n", addr);
        continue;
      }

      offset = addr - text->vma;
      pc = offset + text->bytes;
      n = text->size - offset;

          /*cs_disasm_iter disas one instruction at a time rather than whole buffer
    The pc argument allows capstone to update the pointer each time is called 
    this behaves like program counter
    the addr informs capstone about the virtual memory address of the code
    pointed by pc*/

      while(cs_disasm_iter(dis, &pc, &n, &addr, cs_ins)){
        if (cs_ins->id == X86_INS_INVALID || cs_ins->size == 0){
          break;
        }
        
        seen[cs_ins->address] = true;
        print_ins(cs_ins);

        if (is_flow(cs_ins)){
        /*The example disassembler only parses
immediate control flow targets, so it checks for operands of type X86_OP_IMM
and returns the value of any immediate targets it finds. If this target hasn’t
been disassembled yet, the disasm function adds it to the queue.
*/
          target = immediate_target(cs_ins);


          if (target && !seen[target] && text->contains(target)){
              Q.push(target);
              printf("  -> new target: 0x%016jx\n", target);
          }

          if (is_unconditional_flow(cs_ins)){
            break;
          }
        }

        else if(cs_ins->id == X86_INS_HLT) break;
      }

      printf("*************\n");
 

  }


  cs_free(cs_ins, 1);
  cs_close(&dis);

  return 0;

}


bool
is_cs_ret_ins(cs_insn *ins)
{
  switch(ins->id) {
  case X86_INS_RET:
    return true;
  default:
    return false;
  }
}


int find_gadgets_at_root(Section *text, uint64_t root, map<string, vector<uint64_t>> *gadgets, csh dis){
    size_t n, len;
    const uint8_t *pc;
    uint64_t offset, addr;
    string gadget_str;

    cs_insn *cs_ins;
  /* This is because you want gadgets
of at most five instructions, and since x86 instructions never consist of more
than 15 bytes each,*/

    const size_t max_gadget_len    = 5; /* instructions */
    const size_t x86_max_ins_bytes = 15;
    const uint64_t root_offset     = max_gadget_len*x86_max_ins_bytes;

    cs_ins = cs_malloc(dis);
  if(!cs_ins) {
    fprintf(stderr, "Out of memory\n");
    return -1;
  }

  
  for (uint64_t a = root -1 ; a >= root- root_offset; a--){

    addr = a;
    offset = addr - text->vma;
    pc = offset + text->bytes;
    n = text->size  - offset;
    len = 0;
    gadget_str = "";

        /*For every search offset, the gadget finder performs a linear disassembly
sweep */

    while (cs_disasm_iter(dis, &pc, &n, &addr, cs_ins)){
      if(cs_ins->id == X86_INS_INVALID || cs_ins->size == 0) {
        break;
      }
      /*The gadget finder also breaks off the disassembly sweep if it hits an
instruction with an address beyond the root */
      else if ( cs_ins->address > root){
        break;
      }
      else if (is_flow(cs_ins) && !is_cs_ret_ins(cs_ins)){
        break;
      }
      else if( len ++ > max_gadget_len){
        break;
      }
/*        // Ascii text of instruction mnemonic
        // This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
        char mnemonic[32];

        // Ascii text of instruction operands
        // This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
        char op_str[160];
*/
      gadget_str += string(cs_ins->mnemonic) + " " + string(cs_ins->op_str);
      if (cs_ins->address == root){
          (*gadgets)[gadget_str].push_back(a);
          break;
      }

      gadget_str += "; ";
    }
  }
  cs_free(cs_ins, 1);

  return 0;  
}

int find_gadgets(Binary *bin){

  csh dis;
  Section *text;
  map<string, vector<uint64_t>> gadgets;
  const uint8_t X86_ret_opcode = 0xc3;

  text = bin->get_text_section();
  // printf("vma: 0x%x , " , text->vma);
  if(!text) {
    fprintf(stderr, "Nothing to disassemble\n");
    return 0;
  }

  if (cs_open(CS_ARCH_X86, CS_MODE_64, &dis) != CS_ERR_OK){
      fprintf(stderr, "Failed to open Capstone\n");
      return -1;
  }

  /*Detailed analysis */
  cs_option(dis, CS_OPT_DETAIL, CS_OPT_ON);

  for (size_t i = 0; i < text->size; i++){
      if (text->bytes[i] == X86_ret_opcode){
          if (find_gadgets_at_root(text, text->vma+i, &gadgets, dis) < 0){
            break;
          }
      }
  }

  for (auto &gd : gadgets){
      cout << "Gadget opcode: " << gd.first <<" \t" << endl;
      for (auto &addr : gd.second){
          // cout << "\t\tGadget address: " << addr << endl;
          printf("\tGadget address: 0x%x", addr);
      }
    cout << endl;
  }

  cs_close(&dis); 
  return 0;
}
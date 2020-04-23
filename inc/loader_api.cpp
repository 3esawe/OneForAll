#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <string>
#include <vector>
#include <bfd.h>
#include "loader_api.h"


using namespace std;

static bfd* open_bfd(string& fname){

	static int bfdinit = 0;
	bfd *bfd_h;
	
	if (!bfdinit){
		/*This routine must be called before any other BFD function to initialize magical internal data structures. */
		bfd_init();
		bfdinit = 1;
	}

	/*Open the file filename (using fopen) with the target target. Return a pointer to the created BFD. */
	bfd_h = bfd_openr(fname.c_str(), NULL);

	if(!bfd_h){
    fprintf(stderr, "failed to open binary '%s' (%s)\n",
            fname.c_str(), bfd_errmsg(bfd_get_error()));
    return NULL;
	}


  if(!bfd_check_format(bfd_h, bfd_object)) {
    fprintf(stderr, "file '%s' does not look like an executable (%s)\n",
            fname.c_str(), bfd_errmsg(bfd_get_error()));
    return NULL;
  }

	bfd_set_error(bfd_error_no_error);
	if(bfd_get_flavour(bfd_h) == bfd_target_unknown_flavour) {
    fprintf(stderr, "unrecognized format for binary '%s' (%s)\n",
            fname.c_str(), bfd_errmsg(bfd_get_error()));
    return NULL;
  }


  return bfd_h;

}



static int load_symbols(bfd *bfd_h, Binary *binary){

	int ret; 
	long n, nsyms, i;
	/*Create a new asymbol structure*/
	asymbol **bfd_symtab;
	Symbols *sym;

	bfd_symtab = NULL;
	/*Return the number of bytes required to store a vector of pointers to asymbols for all the symbols in the BFD abfd*/
	n = bfd_get_symtab_upper_bound(bfd_h);

	if (n < 0){
		fprintf(stderr, "failed to read symtab (%s)\n",
		bfd_errmsg(bfd_get_error()));
		goto fail;
	}

	else if (n){
		// alloacating space for the symtab 
		bfd_symtab = (asymbol **) malloc(n);
		
		if(!bfd_symtab) {
			fprintf(stderr, "out of memory\n");
			goto fail;
		}

		/*Read the symbols from the BFD abfd, and fills in the vector location with pointers to the symbols and a trailing NULL.*/		

		nsyms = bfd_canonicalize_symtab(bfd_h, bfd_symtab);

		if (nsyms <  0){
			fprintf(stderr, "failed to read symtab (%s)\n",
			bfd_errmsg(bfd_get_error()));
			goto fail;
		}


		for (i = 0; i < nsyms ; i++){
			/*this will check if this function or not */
			if (bfd_symtab[i]->flags & BSF_FUNCTION){
				binary->symbols.push_back(Symbols());
				sym = &binary->symbols.back();
				sym->Stype = Symbols::FUNC;
				sym->name = string(bfd_symtab[i]->name);
				/*Will get the address of the current symbol*/
				sym->address = bfd_asymbol_value(bfd_symtab[i]);
			}
		}
	}
	  ret = 0;
	goto cleanup;

	fail:
		ret = -1;

	cleanup:
		if(bfd_symtab) free(bfd_symtab);

	return ret;
}




static int load_daynamic_symbols(bfd *bfd_h, Binary *binary){

	int ret; 
	long n, nsyms, i;
	/*Create a new asymbol structure*/
	asymbol **bfd_dynsym;
	Symbols *sym;

	bfd_dynsym = NULL;
	/*Return the number of bytes required to store a vector of pointers to asymbols for all the symbols in the BFD abfd*/
	n = bfd_get_dynamic_symtab_upper_bound(bfd_h);

	if (n < 0){
		fprintf(stderr, "failed to read dynamic symtab  (%s)\n",
		bfd_errmsg(bfd_get_error()));
		goto fail;
	}

	else if (n){
		// alloacating space for the symtab 
		bfd_dynsym = (asymbol **) malloc(n);
		
		if(!bfd_dynsym) {
			fprintf(stderr, "out of memory\n");
			goto fail;
		}

		/*Read the symbols from the BFD abfd, and fills in the vector location with pointers to the symbols and a trailing NULL.*/		

		nsyms = bfd_canonicalize_dynamic_symtab(bfd_h, bfd_dynsym);

		if (nsyms <  0){
			fprintf(stderr, "failed to read dynamic symtab (%s)\n",
			bfd_errmsg(bfd_get_error()));
			goto fail;
		}


		for (i = 0; i < nsyms ; i++){
			/*this will check if this function or not */
			if (bfd_dynsym[i]->flags & BSF_FUNCTION){
				binary->symbols.push_back(Symbols());
				sym = &binary->symbols.back();
				sym->Stype = Symbols::FUNC;
				sym->name = string(bfd_dynsym[i]->name);
				/*Will get the address of the current symbol*/
				sym->address = bfd_asymbol_value(bfd_dynsym[i]);
			}
		}
	}
	  ret = 0;
	goto cleanup;

	fail:
		ret = -1;

	cleanup:
		if(bfd_dynsym) free(bfd_dynsym);

	return ret;
}


static int load_sections(bfd *bfd_h, Binary *binary){

	int bfd_flags; 
	uint64_t vma, size; 
	const char *secname; 

	asection* bfd_sec;
	Section *sec; 
	Section::SectionType sectype;

	for (bfd_sec = bfd_h->sections; bfd_sec; bfd_sec = bfd_sec->next){
		/*This is to decide what type of section is this we are intrested in code and data*/
		bfd_flags = bfd_get_section_flags(bfd_h, bfd_sec);
		sectype = Section::NONE;
		if (bfd_flags & SEC_CODE){
			sectype = Section::CODE;
		}
		else if (bfd_flags & SEC_DATA){
			sectype = Section::DATA;
		}

		else {
			continue;
		}
		/*Get the section memory address and size and name*/
	    vma     = bfd_section_vma(bfd_h, bfd_sec);
	    size    = bfd_section_size(bfd_h, bfd_sec);
	    secname = bfd_section_name(bfd_h, bfd_sec);

	    if (!secname){
	    	secname = "<unamed_section>";
	    }
	    /*So this basically works by first pushing A Section object to a vector container
	    Then get it back by call by refrence then fill up his properties */
	    binary->sections.push_back(Section());
	    sec = &binary->sections.back();
	    sec->name = string(secname);
	    sec->Stype = sectype;
	    sec->vma = vma;
	    sec->size = size;
	    sec->bytes = (uint8_t *) malloc(size);
	    if(!sec->bytes) {
	      fprintf(stderr, "out of memory\n");
	      return -1;
	    }

	    if(!bfd_get_section_contents(bfd_h, bfd_sec, sec->bytes, 0, size)) {
	      fprintf(stderr, "failed to read section '%s' (%s)\n",
	              secname, bfd_errmsg(bfd_get_error()));
	      return -1;
	    }
	}

	return 0;
}

static int load_binary_bfd(string &fname,  Binary *bin, Binary::BinaryType type){
	int ret;
	bfd *bfd_h;

	const bfd_arch_info_type *bfd_info;

	bfd_h = NULL;

	bfd_h = open_bfd(fname);

	bin->filename = string(fname);
	/*This will get the address of the starting binary*/
	bin->entry = bfd_get_start_address(bfd_h);
	/*Getting the bunary */
	/*bfd_h->xvec gives you a pointer to a bfd_target structure*/
	bin->Bname = string(bfd_h->xvec->name);
	/*The loader copies this string into the Binary
object Ì. Next, it inspects the bfd_h->xvec->flavour field using a switch and
sets the type of the Binary accordingly*/
	switch(bfd_h->xvec->flavour){
		case bfd_target_elf_flavour:
			bin->Btype = Binary::ELF;
			break;
		case bfd_target_coff_flavour:
			bin->Btype = Binary::PE;
			break;
		  case bfd_target_unknown_flavour:
		  default:
		    fprintf(stderr, "unsupported binary type (%s)\n", bfd_h->xvec->name);
		    goto fail;

	}
	/*Return the architecture info struct in abfd. */
	bfd_info = bfd_get_arch_info(bfd_h);

	bin->Aname = string(bfd_info->printable_name);
	/*The bfd_arch_info_type data structure also contains a field called mach Ð,
which is just an integer identifier for the architecture */
  switch(bfd_info->mach) {
  case bfd_mach_i386_i386:
    bin->Atype = Binary::ARCH_x86; 
    bin->bits = 32;
    break;
  case bfd_mach_x86_64:
    bin->Atype = Binary::ARCH_x86;
    bin->bits = 64;
    break;
  default:
    fprintf(stderr, "unsupported architecture (%s)\n",
            bfd_info->printable_name);
    goto fail;
  }


    /* Symbols handling is best-effort only (they may not even be present) */
	  load_symbols(bfd_h, bin);
	  load_daynamic_symbols(bfd_h, bin);

	  if(load_sections(bfd_h, bin) < 0) goto fail;

	  ret = 0;
	  goto cleanup;

	fail:
	  ret = -1;

	cleanup:
	  if(bfd_h) bfd_close(bfd_h);

	  return ret;

}


int
load_binary(string &fname, Binary *bin, Binary::BinaryType type)
{
  return load_binary_bfd(fname, bin, type);
}


void
unload_binary(Binary *bin)
{
  size_t i;
  Section *sec;

  for(i = 0; i < bin->sections.size(); i++) {
    sec = &bin->sections[i];
    if(sec->bytes) {
      free(sec->bytes);
    }
  }
}

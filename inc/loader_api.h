#ifndef LOADER
#define LOADER


#include <vector>
#include <string>
#include <stdint.h>


using namespace std;


class Binary;
class Symbols;
class Section;


class Symbols
{
public:
	

	enum  SymType 
	{
		NONE_FUNC = 0,
		FUNC = 1
	  	 // Warning!: constant value truncated
	};


	Symbols(): name(), Stype(SymType::NONE_FUNC), address(0){}



	string name;
	SymType Stype;
	uint64_t address;
};



class Section{
	
	public:


	enum SectionType{
		NONE = 0,
		CODE = 1,
		DATA = 2
	};

	Section():binary(NULL),Stype(NONE),vma(0), size(0),bytes(0){}
	~Section();

	bool contains(uint64_t addr){
		return (addr >= vma) && (addr-vma < size);
	}

	string name;
	Binary *binary;
	SectionType Stype;
	uint64_t vma;
	uint64_t size;
	uint8_t *bytes;
};



class Binary
{
	public:
	enum BinaryType {
		AUTO = 0,
		ELF = 1,
		PE = 2
	};

	enum  BinaryArch  {
		ARCH_NONE = 0,
		ARCH_x86 = 1
	};
	
	Binary(): Btype(AUTO), Atype(ARCH_NONE), bits(0), entry(0){}

	string filename;
	BinaryType Btype;
	string Bname;
	BinaryArch Atype;
	string Aname;
	unsigned bits;
	uint64_t entry;
	vector<Symbols> symbols;
	vector<Section> sections;

	Section *get_text_section() { for(auto &s : sections) if(s.name == ".text") return &s; return NULL; }
};




int load_binary(string &fname,  Binary *bin, Binary::BinaryType Btype);
void unload_binary(Binary *bin);



#endif /*LOADER*/
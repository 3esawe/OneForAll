CXX=g++
OBJ=agumon

.PHONY: all clean

all: $(OBJ)

loader_api.o: inc/loader_api.cpp
	$(CXX) -std=c++11 -c inc/loader_api.cpp

agumon: loader_api.o agumon.cpp
	$(CXX) -std=c++11 -o agumon agumon.cpp loader_api.o -lbfd -lcapstone

clean:
	rm -f $(OBJ) *.o


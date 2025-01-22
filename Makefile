EXE=
LIB_FILES=src/preload.cpp

all: 
	make app
	make lib
	make run

lib: $(LIB_FILES)
	mkdir -p lib
	g++ -fPIC -shared  -o lib/libpreload.so $(LIB_FILES) -ldl -lseccomp

app: main.cpp
	mkdir -p bin
	g++ main.cpp -o bin/exe.out

run:
	LD_PRELOAD=./lib/libpreload.so bin/exe.out

run_exe: lib
	LD_PRELOAD=./lib/libpreload.so $(EXE)

clean:
	mkdir -p bin lib  2>/dev/null
	rm -rf bin lib 

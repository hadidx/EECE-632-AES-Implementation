.RECIPEPREFIX = >
# compiler settings
CXX = g++
# use flags to generate dependency files
CXXFLAGS = -std=c++14 -MMD -MP
# object file generation path
tmpDir = .objs
# modules path
modPath = ./modules
testFrameworkPath = ../simpletest
testPath = ./tests

# Names of modules and files to be compiled
names := main.o
names += $(patsubst $(modPath)/%.cpp,%.o,$(shell find $(modPath) -iname "*.cpp"))
# prepend tmpDir
names := $(addprefix $(tmpDir)/, $(names))

# there should be a dep file for every object file
# deps  := $(patsubst %.o,%.d,$(names))


testNames := test_main.o
testNames += $(patsubst $(modPath)/%.cpp,%.o,$(shell find $(modPath) -iname "*.cpp"))
testNames += $(patsubst $(testPath)/%.cpp,%.o,$(shell find $(testPath) -iname "*.cpp"))
testNames += $(patsubst $(testFrameworkPath)/%.cpp,%.o,$(shell find $(testFrameworkPath) -iname "*.cpp"))
testNames := $(addprefix $(tmpDir)/, $(testNames))

deps  := $(patsubst %.o,%.d,$(testNames))

all: test_main main
%.o : %.cpp


# Linking
main: $(names)
>$(CXX) $(CXXFLAGS) -o main $^

test_main: $(testNames)
>$(CXX) $(CXXFLAGS) -o test_main $^ -I "$(testFrameworkPath)" -I "$(testPath)" -I "$(modPath)"
# Rule for main file
$(tmpDir)/main.o: main.cpp
>@mkdir -p $(tmpDir)
>$(CXX) $(CXXFLAGS) -c main.cpp -o $@ -I "$(modPath)"

# Rule for test_main file
$(tmpDir)/test_main.o: test_main.cpp
>@mkdir -p $(tmpDir)
>$(CXX) $(CXXFLAGS) -c test_main.cpp -o $@ -I "$(modPath)" -I "$(testFrameworkPath)" -I "$(testPath)"

# rules for module files
$(tmpDir)/%.o: $(modPath)/%.cpp
>mkdir -p $(dir $@)
>$(CXX) $(CXXFLAGS) -c $< -o $@

$(tmpDir)/%.o: $(testPath)/%.cpp
>mkdir -p $(dir $@)
>$(CXX) $(CXXFLAGS) -c $< -o $@ -I "$(modPath)" -I "$(testFrameworkPath)" -I "$(testPath)"

# rules for testFramework files
$(tmpDir)/%.o: $(testFrameworkPath)/%.cpp
>mkdir -p $(dir $@)
>$(CXX) $(CXXFLAGS) -c $< -o $@



# include the dependencies if they exist    
-include $(deps)

clean:
>rm -rf *.o main test_main $(tmpDir) $(deps)
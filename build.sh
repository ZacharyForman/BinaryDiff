#!/bin/bash

# Constructs a makefile for the project
# and then calls make with the arguments
# given to this script.
#
# Overwrites any present file called 'makefile'.

bin_dir="bin"
obj_dir="obj"
src_dir="./"
srcs=$(find ${src_dir} -name '*.cc')

mkdir -p ${bin_dir}

mkdir -p ${obj_dir}

objects=""
binary="${bin_dir}/binary-matcher"
rules=""

# Make object rules
for file in $srcs; do
  file=${file/$src_dir/}

  # If the output directory doesn't exist, create it.
  mkdir -p ${obj_dir}/$(dirname $file)

  obj="$file"
  obj="${obj_dir}/${obj/%cc/o}"
  objects="$obj $objects"
  dependency=$(g++ -I${src_dir} -MM -MT "$obj" -std=c++14 $file)
  # Remove implanted newlines
  dependency=$(echo $dependency | sed 's/ \\//g')
  rule=$(printf '%s\n\t$(CC) $(CFLAGS) %s -o %s' "$dependency" "$file" "$obj")
  # Add the rule to the ruleset.
  rules=$(printf '%s\n\n%s' "$rules" "$rule")
done

WARNINGS='-fmax-errors=5 -fstrict-aliasing -fstrict-overflow
          -pedantic -pedantic-errors -Wabi -Wall -Warray-bounds=2
          -Wbool-compare -Wcast-align -Wcast-qual -Wchar-subscripts
          -Wcomment -Wconversion -Wctor-dtor-privacy -Wdate-time
          -Wdisabled-optimization -Weffc++ -Wenum-compare -Werror
          -Wextra -Wfloat-equal -Wformat-nonliteral -Wformat-security
          -Wformat-y2k -Wformat=5 -Wimport -Winit-self -Winline
          -Winvalid-pch -Wlogical-op -Wlogical-op -Wmaybe-uninitialized
          -Wmissing-braces -Wmissing-declarations -Wmissing-field-initializers
          -Wmissing-format-attribute -Wmissing-format-attribute
          -Wmissing-include-dirs -Wmissing-noreturn -Wnoexcept -Wold-style-cast
          -Woverloaded-virtual -Wpacked -Wparentheses -Wpointer-arith
          -Wredundant-decls -Wreturn-type -Wsequence-point -Wshadow
          -Wsign-compare -Wsign-conversion -Wsign-promo -Wstack-protector
          -Wstrict-aliasing=1 -Wstrict-null-sentinel -Wstrict-overflow=5
          -Wsuggest-override -Wswitch-bool -Wswitch-default -Wswitch-enum
          -Wtrigraphs -Wtype-limits -Wundef -Wundef -Wuninitialized
          -Wunknown-pragmas -Wunreachable-code -Wunsafe-loop-optimizations
          -Wunused -Wunused -Wunused-function -Wunused-label -Wunused-parameter
          -Wunused-value -Wunused-variable -Wvariadic-macros
          -Wvolatile-register-var -Wwrite-strings
          -Wzero-as-null-pointer-constant'

# build the actual makefile
echo 'CC=g++' > makefile
echo >> makefile
echo CFLAGS=$WARNINGS -c -O2 -std=c++14 -I${src_dir} >> makefile
echo LINKFLAGS=-std=c++14 >> makefile
echo >> makefile
echo "OBJ=$objects" >> makefile
echo "BIN=$binary" >> makefile
echo >> makefile
printf '%s:%s\n\n' 'all' ' $(OBJ) $(BIN)' >> makefile
printf '%s\n\t%s\n\n' 'clean:' 'rm -rf $(OBJ) $(BIN)' >> makefile
printf "%s:%s\n\t%s" \
       "$binary" \
       "$objects" \
       '$(CC) -o $(BIN) $(OBJ) $(LINKFLAGS)' >> makefile
echo "$rules" >> makefile

make "$@"

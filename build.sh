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

# build the actual makefile
echo 'CC=g++' > makefile
echo >> makefile
echo CFLAGS=-Wall -c -O2 -std=c++14 -I${src_dir} >> makefile
echo LINKFLAGS=-Wall -std=c++14 >> makefile
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

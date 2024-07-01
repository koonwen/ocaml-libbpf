#!/bin/bash

SOURCE_BRANCH="main"
TARGET_BRANCH="vendored"
TEMP_DIR="tmp"

# Associative array to map source files to target locations
declare -A FILE_MAP
FILE_MAP=(
  ["src/bindings/c_type_description.ml"]="src/c_type_description.ml"
  ["src/bindings/c_function_description.ml"]="src/c_function_description.ml"
  ["src/bindings/c.ml"]="src/c.ml"

  ["src/ocaml_libbpf.ml"]="src/ocaml_libbpf.ml"
  ["src/ocaml_libbpf.mli"]="src/ocaml_libbpf.mli"

  ["src/ocaml_libbpf_maps/ocaml_libbpf_maps.ml"]="src/ocaml_libbpf_maps/ocaml_libbpf_maps.ml"
  ["src/ocaml_libbpf_maps/ocaml_libbpf_maps.mli"]="src/ocaml_libbpf_maps/ocaml_libbpf_maps.mli"
)

# Check out the source branch
git checkout $SOURCE_BRANCH

# Create the temporary directory
mkdir -p $TEMP_DIR

# Copy the selected files to the temporary directory
for SRC_FILE in "${!FILE_MAP[@]}"
do
  cp -r $SRC_FILE $TEMP_DIR
done

# Check out the target branch
git checkout $TARGET_BRANCH

# Copy the files from the temporary directory to the target branch
for SRC_FILE in "${!FILE_MAP[@]}"
do
  TARGET_FILE=${FILE_MAP[$SRC_FILE]}
  cp -r $TEMP_DIR/$(basename $SRC_FILE) $TARGET_FILE
done

# Stage and commit the changes
# git add .
# git commit -m "Synced selected files from $SOURCE_BRANCH to $TARGET_BRANCH"

# Clean up the temporary directory
rm -rf $TEMP_DIR

# End of script

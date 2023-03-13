#!/bin/sh -e

LIBRS_DIR=$BASE_DIR/core/librs
cd $LIBRS_DIR

export RUSTFLAGS="-O -Cstrip=debuginfo -Copt-level=z \
		-Dunsafe_op_in_unsafe_fn -Drust_2018_idioms \
		-Dunreachable_pub -Dnon_ascii_idents \
		-Wmissing_docs \
		-Drustdoc::missing_crate_level_docs \
		-Dclippy::correctness -Dclippy::style \
		-Dclippy::suspicious -Dclippy::complexity \
		-Dclippy::perf \
		-Dclippy::let_unit_value -Dclippy::mut_mut \
		-Dclippy::needless_bitwise_bool \
		-Dclippy::needless_continue \
		-Wclippy::dbg_macro"
#		-Zbinary_dep_depinfo=y

cargo build --target=aarch64-unknown-linux-gnu
cbindgen --config cbindgen.toml --output generated-include/kvms_rs.h --lang c ./

# TODO: remove this mkdir and make workaround patch
mkdir -p $BASE_DIR/.objs/virt
cp $LIBRS_DIR/target/aarch64-unknown-linux-gnu/debug/libkvms_rs.a $BASE_DIR/.objs/
cd $BASE_DIR


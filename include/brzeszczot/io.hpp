#ifndef BRZESZCZOT_IO_HPP
#define BRZESZCZOT_IO_HPP

#include "brzeszczot.hpp"
#include "libriot.h"

namespace brzeszczot {
	bool try_read_bin_file(char const *filepath, struct riot_bin *out);
	bool try_write_bin_file(char const *filepath, struct riot_bin *bin);
};

#endif /* BRZESZCZOT_IO_HPP */

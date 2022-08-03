#ifndef BRZESZCZOT_IO_HPP
#define BRZESZCZOT_IO_HPP

#include "brzeszczot.hpp"
#include "libriot.h"

namespace brzeszczot {
	bool try_read_file(char const *filepath, struct riot_bin *out);
};

#endif /* BRZESZCZOT_IO_HPP */

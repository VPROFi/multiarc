#include <unistd.h>
#include <memory>
#include <mutex>
#include <set>
#include <fcntl.h>
#include <string.h>
#include <ftw.h>

#include <utils.h>
#include <os_call.hpp>
#include <ScopeHelpers.h>

#include "libarch_utils.h"
#include "libarch_cmd.h"

static bool PartsMatchesWanted(const std::vector<std::string> &wanted, const std::vector<std::string> &parts)
{
	size_t i = 0;
	while (i != wanted.size() && i != parts.size() && (wanted[i] == parts[i] || wanted[i] == "*")) {
		++i;
	}

	return (i == wanted.size());
}

static bool PartsMatchesAnyOfWanteds(const std::vector<std::vector<std::string> > &wanteds, const std::vector<std::string> &parts)
{
	for (const auto &w : wanteds) {
		if (PartsMatchesWanted(w, parts)) {
			return true;
		}
	}

	return false;
}

static bool LIBARCH_CommandReadWanteds(const char *cmd, LibArchOpenRead &arc,
	const size_t root_count, const std::vector<std::vector<std::string> > &wanteds)
{
	std::string src_path, extract_path;
	std::vector<std::string> parts;

	bool out = true;
	for (;;) {
		struct archive_entry *entry = arc.NextHeader();
		if (!entry) {
			break;
		}

		const char *pathname = LibArch_EntryPathname(entry);
		src_path = pathname ? pathname : "";
		parts.clear();
		LibArch_ParsePathToParts(parts, src_path);

		if (parts.empty()) {
			fprintf(stderr, "Empty path: '%s' '%ls'\n",
				pathname, archive_entry_pathname_w(entry));
			arc.SkipData();
			continue;
		}

		if (!wanteds.empty() && !PartsMatchesAnyOfWanteds(wanteds, parts)) {
//			fprintf(stderr, "Not matching: '%s' '%ls'\n", pathname, archive_entry_pathname_w(entry));
			arc.SkipData();
			continue;
		}

		switch (*cmd) {
			case 'X': {
				extract_path = '.';
				size_t root_dismiss_counter = root_count;
				for (const auto &p : parts) {
					if (root_dismiss_counter == 0) {
						mkdir(extract_path.c_str(),
							S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH | S_IXUSR | S_IXGRP | S_IXOTH);
						extract_path+= '/';
						extract_path+= p;
					} else {
						--root_dismiss_counter;
					}
				}
			} break;

			case 'x': {
				extract_path = "./";
				extract_path+= parts.back();
			} break;

			case 't':
			default:
				extract_path = "/dev/null";
		}

		archive_entry_set_pathname(entry, extract_path.c_str() );
		int r = archive_read_extract(arc.Get(), entry, ARCHIVE_EXTRACT_TIME); // ARCHIVE_EXTRACT_PERM???
		if (r != ARCHIVE_OK && r != ARCHIVE_WARN) {
			fprintf(stderr, "Error %d (%s): '%s' -> '%s'\n",
				r, archive_error_string(arc.Get()),
				src_path.c_str(), extract_path.c_str());
			out = false;

		} else {
			fprintf(stderr, "Extracted: '%s' -> '%s'\n",
				src_path.c_str(), extract_path.c_str());

		    struct stat s;
			if (wanteds.size() == 1 && wanteds[0] == parts
			  && stat(extract_path.c_str(), &s) == 0 && !S_ISDIR(s.st_mode)) {
				break; // nothing to search more here
			}
		}
	}

	return out;
}

bool LIBARCH_CommandRead(const char *cmd, const char *arc_path, const LibarchCommandOptions &arc_opts, int files_cnt, char *files[])
{
	std::vector<std::vector<std::string> > wanteds;
	wanteds.reserve(files_cnt);

	std::vector<std::string> root;
	if (!arc_opts.root_path.empty()) {
		LibArch_ParsePathToParts(root, arc_opts.root_path);
	}

	for (int i = 0; i < files_cnt; ++i) {
		wanteds.emplace_back();
		if (files[i]) {
			if (*files[i]) {
				LibArch_ParsePathToParts(wanteds.back(), std::string(files[i]));
			}
			if (!root.empty() && !LibArch_PartsStartsBy(wanteds.back(), root)) {
				fprintf(stderr, "Fixup root for path: '%s'\n", files[i]);
				wanteds.back().insert(wanteds.back().begin(), root.begin(), root.end());
			}
		}

		if (wanteds.back().empty()) {
			fprintf(stderr, "Skipping empty path: '%s'\n", files[i]);
			wanteds.pop_back();
		}
	}

	if (wanteds.empty() && files_cnt > 0) {
		return false;
	}

	LibArchOpenRead arc(arc_path, cmd, arc_opts.charset.c_str());
	return LIBARCH_CommandReadWanteds(cmd, arc, root.size(), wanteds);
}

/***************************************************************************
 *            lpconfig.c
 *
 *  Thu Mar 10 11:13:44 2005
 *  Copyright  2005  Simon Morlat
 *  Email simon.morlat@linphone.org
 ****************************************************************************/

/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#define MAX_LEN 2048

#include <sys/stat.h>

#define lp_new0(type, n) (type *) calloc(sizeof(type), n)

#include "lpconfig.h"
#include <list>
#include <algorithm>
#include <ortp/ortp.h>

using namespace std;

namespace flexisip {

struct LpItem {
	char *key;
	char *value;
	int is_read;
	int lineno;
};

struct LpSection {
	char *name;
	list<LpItem *> items;
};

struct LpConfig {
	FILE *file;
	char *filename;
	list<LpSection *> sections;
	int modified;
	int readonly;
};

LpItem *lp_item_new(const char *key, const char *value) {
	LpItem *item = new LpItem();
	item->key = strdup(key);
	item->value = strdup(value);
	return item;
}

LpSection *lp_section_new(const char *name) {
	LpSection *sec = new LpSection();
	sec->name = ortp_strdup(name);
	return sec;
}

void lp_item_destroy(LpItem *item) {
	free(item->key);
	free(item->value);
	delete (item);
}

void lp_section_destroy(LpSection *sec) {
	free(sec->name);
	for (auto it = sec->items.cbegin(); it != sec->items.cend(); ++it) {
		lp_item_destroy(*it);
	}
	sec->items.clear();
	delete (sec);
}

void lp_section_add_item(LpSection *sec, LpItem *item) {
	sec->items.push_back(item);
}

void lp_config_add_section(LpConfig *lpconfig, LpSection *section) {
	lpconfig->sections.push_back(section);
}

void lp_config_remove_section(LpConfig *lpconfig, LpSection *section) {
	lpconfig->sections.remove(section);
	lp_section_destroy(section);
}

static bool_t is_first_char(const char *start, const char *pos) {
	const char *p;
	for (p = start; p < pos; p++) {
		if (*p != ' ')
			return false;
	}
	return true;
}

struct LpSectionComp {
	explicit LpSectionComp(const char *name) : name(name) {
	}
	inline bool operator()(const LpSection *sec) const {
		return strcasecmp(sec->name, name) == 0;
	}

  private:
	const char *name;
};
LpSection *lp_config_find_section(LpConfig *lpconfig, const char *name) {
	auto it = find_if(lpconfig->sections.cbegin(), lpconfig->sections.cend(), LpSectionComp(name));
	return it != lpconfig->sections.cend() ? *it : NULL;
}

struct LpItemComp {
	explicit LpItemComp(const char *key) : key(key) {
	}
	inline bool operator()(const LpItem *item) const {
		return strcasecmp(item->key, key) == 0;
	}

  private:
	const char *key;
};
LpItem *lp_section_find_item(LpSection *sec, const char *name) {
	auto it = find_if(sec->items.cbegin(), sec->items.cend(), LpItemComp(name));
	if (it == sec->items.cend())
		return NULL;
	(*it)->is_read = true;
	return *it;
}

static int is_a_comment(const char *str) {
	while (*str == ' ') {
		str++;
	}
	if (*str == '#')
		return 1;
	return 0;
}

void lp_config_parse(LpConfig *lpconfig, FILE *file) {
	char tmp[MAX_LEN];
	LpSection *cur = NULL;
	int line = 0;

	if (file == NULL)
		return;

	while (fgets(tmp, MAX_LEN, file) != NULL) {
		char *pos1, *pos2;
		line++;
		if (is_a_comment(tmp))
			continue;
		pos1 = strchr(tmp, '[');
		if (pos1 != NULL && is_first_char(tmp, pos1)) {
			pos2 = strchr(pos1, ']');
			if (pos2 != NULL) {
				int nbs;
				char secname[MAX_LEN];
				secname[0] = '\0';
				/* found section */
				*pos2 = '\0';
				nbs = sscanf(pos1 + 1, "%s", secname);
				if (nbs == 1) {
					if (strlen(secname) > 0) {
						cur = lp_config_find_section(lpconfig, secname);
						if (cur == NULL) {
							cur = lp_section_new(secname);
							lp_config_add_section(lpconfig, cur);
						}
					}
				} else {
					ortp_warning("parse error!");
				}
			}
		} else {
			pos1 = strchr(tmp, '=');
			if (pos1 != NULL) {
				char key[MAX_LEN];
				key[0] = '\0';

				*pos1 = '\0';
				if (sscanf(tmp, "%s", key) > 0) {

					pos1++;
					pos2 = strchr(pos1, '\n');
					if (pos2 == NULL)
						pos2 = pos1 + strlen(pos1);
					else {
						*pos2 = '\0'; /*replace the '\n' */
						pos2--;
					}
					/* remove ending white spaces */
					for (; pos2 > pos1 && *pos2 == ' '; pos2--)
						*pos2 = '\0';
					if (pos2 - pos1 >= 0) {
						/* found a pair key,value */
						if (cur != NULL) {
							LpItem *item = lp_section_find_item(cur, key);
							if (item == NULL) {
								item = lp_item_new(key, pos1);
								lp_section_add_item(cur, item);
							} else {
								free(item->value);
								item->value = strdup(pos1);
							}
							item->lineno = line;
							/*printf("Found %s %s=%s\n",cur->name,key,pos1);*/
						} else {
							ortp_warning("found key,item but no sections");
						}
					}
				}
			}
		}
	}
}

LpConfig *lp_config_new(const char *filename) {
	LpConfig *lpconfig = new LpConfig();
	if (filename != NULL) {
		ortp_message("Loading configuration file from [%s]", filename);
		lpconfig->filename = ortp_strdup(filename);
		lpconfig->file = fopen(filename, "rw");
		if (lpconfig->file != NULL) {
			lp_config_parse(lpconfig, lpconfig->file);
			fclose(lpconfig->file);
#if 0
			/* make existing configuration files non-group/world-accessible */
			if (chmod(filename, S_IRUSR | S_IWUSR) == -1)
				ortp_warning("unable to correct permissions on "
				  	  "configuration file: %s",
					   strerror(errno));
#endif /*_WIN32_WCE*/
			lpconfig->file = NULL;
			lpconfig->modified = 0;
		}
	}
	return lpconfig;
}

int lp_config_read_file(LpConfig *lpconfig, const char *filename) {
	FILE *f = fopen(filename, "r");
	if (f != NULL) {
		lp_config_parse(lpconfig, f);
		fclose(f);
		return 0;
	}
	ortp_warning("Fail to open file %s", filename);
	return -1;
}

void lp_item_set_value(LpItem *item, const char *value) {
	free(item->value);
	item->value = ortp_strdup(value);
}

void lp_config_for_each_unread(LpConfig *lpconfig, LpConfigUnreadCallback cb, void *data) {
	for (auto elem = lpconfig->sections.cbegin(); elem != lpconfig->sections.cend(); ++elem) {
		LpSection *sec = *elem;
		for (auto it = sec->items.cbegin(); it != sec->items.cend(); ++it) {
			LpItem *item = *it;
			if (item->is_read == false) {
				cb(data, sec->name, item->key, item->lineno);
			}
		}
	}
}

void lp_config_destroy(LpConfig *lpconfig) {
	if (lpconfig->filename != NULL)
		free(lpconfig->filename);
	for (auto elem = lpconfig->sections.cbegin(); elem != lpconfig->sections.cend(); ++elem) {
		lp_section_destroy(*elem);
	}
	lpconfig->sections.clear();
	delete (lpconfig);
}

void lp_section_remove_item(LpSection *sec, LpItem *item) {
	sec->items.remove(item);
	lp_item_destroy(item);
}

const char *skip_initial_blanks(const char *str){
	while(*str == ' ') ++str;
	return str;
}

const char *lp_config_get_string(LpConfig *lpconfig, const char *section, const char *key, const char *default_string) {
	LpSection *sec;
	LpItem *item;
	sec = lp_config_find_section(lpconfig, section);
	if (sec != NULL) {
		item = lp_section_find_item(sec, key);
		if (item != NULL)
			return skip_initial_blanks(item->value);
	}
	return default_string;
}

int lp_config_get_int(LpConfig *lpconfig, const char *section, const char *key, int default_value) {
	const char *str = lp_config_get_string(lpconfig, section, key, NULL);
	if (str != NULL)
		return atoi(str);
	else
		return default_value;
}

float lp_config_get_float(LpConfig *lpconfig, const char *section, const char *key, float default_value) {
	const char *str = lp_config_get_string(lpconfig, section, key, NULL);
	float ret = default_value;
	if (str == NULL)
		return default_value;
	sscanf(str, "%f", &ret);
	return ret;
}

void lp_config_set_string(LpConfig *lpconfig, const char *section, const char *key, const char *value) {
	LpItem *item;
	LpSection *sec = lp_config_find_section(lpconfig, section);
	if (sec != NULL) {
		item = lp_section_find_item(sec, key);
		if (item != NULL) {
			if (value != NULL)
				lp_item_set_value(item, value);
			else
				lp_section_remove_item(sec, item);
		} else {
			if (value != NULL)
				lp_section_add_item(sec, lp_item_new(key, value));
		}
	} else if (value != NULL) {
		sec = lp_section_new(section);
		lp_config_add_section(lpconfig, sec);
		lp_section_add_item(sec, lp_item_new(key, value));
	}
	lpconfig->modified++;
}

void lp_config_set_int(LpConfig *lpconfig, const char *section, const char *key, int value) {
	char tmp[30];
	snprintf(tmp, 30, "%i", value);
	lp_config_set_string(lpconfig, section, key, tmp);
	lpconfig->modified++;
}

void lp_item_write(LpItem *item, FILE *file) {
	fprintf(file, "%s=%s\n", item->key, item->value);
}

void lp_section_write(LpSection *sec, FILE *file) {
	fprintf(file, "[%s]\n", sec->name);
	for (auto it = sec->items.cbegin(); it != sec->items.cend(); ++it) {
		lp_item_write(*it, file);
	}
	fprintf(file, "\n");
}

int lp_config_sync(LpConfig *lpconfig) {
	FILE *file;
	if (lpconfig->filename == NULL)
		return -1;
	if (lpconfig->readonly)
		return 0;
#ifndef WIN32
	/* don't create group/world-accessible files */
	(void)umask(S_IRWXG | S_IRWXO);
#endif
	file = fopen(lpconfig->filename, "w");
	if (file == NULL) {
		ortp_warning("Could not write %s ! Maybe it is read-only. Configuration will not be saved.",
					 lpconfig->filename);
		lpconfig->readonly = 1;
		return -1;
	}
	for (auto elem = lpconfig->sections.cbegin(); elem != lpconfig->sections.cend(); ++elem) {
		lp_section_write(*elem, file);
	}
	fclose(file);
	lpconfig->modified = 0;
	return 0;
}

int lp_config_has_section(LpConfig *lpconfig, const char *section) {
	if (lp_config_find_section(lpconfig, section) != NULL)
		return 1;
	return 0;
}

void lp_config_clean_section(LpConfig *lpconfig, const char *section) {
	LpSection *sec = lp_config_find_section(lpconfig, section);
	if (sec != NULL) {
		lp_config_remove_section(lpconfig, sec);
	}
	lpconfig->modified++;
}

int lp_config_needs_commit(const LpConfig *lpconfig) {
	return lpconfig->modified > 0;
}
};//namespace

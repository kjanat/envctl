#ifndef ENVCTL_CLI_H
#define ENVCTL_CLI_H

typedef enum {
	CMD_SET,
	CMD_GET,
	CMD_DISABLE,
	CMD_ENABLE,
	CMD_DELETE,
	CMD_LIST,
	CMD_REDACT,
	CMD_ENV,
	CMD_COUNT
} CmdId;

typedef enum {
	FLAG_DRY_RUN,
	FLAG_VALUES,
	FLAG_ALL,
	FLAG_SORT,
	FLAG_ENV,
	FLAG_NO_ENV,
	FLAG_REDACT,
	FLAG_RAW,
	FLAG_PARANOID,
	FLAG_COUNT
} FlagId;

#define CMD_BIT(id) (1u << (unsigned)(id))

typedef struct {
	CmdId id;
	const char *name;
	const char *alias;
	const char *args;
	const char *summary;
	const char *description;
} Command;

typedef struct {
	FlagId id;
	const char *name;
	unsigned commands;
	const char *summary;
	const char *description;
} Flag;

extern const Command cli_commands[CMD_COUNT];
extern const Flag cli_flags[FLAG_COUNT];

const Command *cli_command_by_name(const char *name);
const Flag *cli_flag_by_name(const char *name);

#endif

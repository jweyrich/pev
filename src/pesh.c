/*
	pev - the PE file analyzer toolkit

	pesh.c - ...

	Copyright (C) 2014 pev authors

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "common.h"
#include <readline/readline.h>
#include <readline/history.h>
#include <errno.h>
#include <string.h>
#include <wordexp.h> // Used for tilde expansion
#include "compat/strlcat.h"
#include "pesh_str.h"

// ----------------------------------------------------------------------------

#define PROGRAM "pesh"
#define HISTORY_FILE "~/.pesh_history"

typedef struct {
	bool is_exiting;
} options_t;

static void usage(void)
{
	printf("Usage: %s [OPTIONS] FILE\n"
		"....\n"
		"\nExample: %s wordpad.exe\n"
		"\nOptions:\n"
		" -v, --version                          show version and exit\n"
		" --help                                 show this help and exit\n",
		PROGRAM, PROGRAM);
}

static void free_options(options_t *options)
{
	if (options == NULL)
		return;

	free(options);
}

static options_t *parse_options(int argc, char *argv[])
{
	options_t *options = malloc_s(sizeof(options_t));
	memset(options, 0, sizeof(options_t));

	/* Parameters for getopt_long() function */
	static const char short_options[] = "v";

	static const struct option long_options[] = {
		{ "help",		no_argument,	NULL,	 1  },
		{ "version",	no_argument,	NULL,	'v' },
		{ NULL,			0,				NULL, 	 0  }
	};

	int c, ind;

	while ((c = getopt_long(argc, argv, short_options, long_options, &ind)))
	{
		if (c < 0)
			break;

		switch (c)
		{
			case 1: // --help option
				usage();
				exit(EXIT_SUCCESS);
			case 'v':
				printf("%s %s\n%s\n", PROGRAM, TOOLKIT, COPY);
				exit(EXIT_SUCCESS);
			default:
				fprintf(stderr, "%s: try '--help' for more information\n", PROGRAM);
				exit(EXIT_FAILURE);
		}
	}

	return options;
}

// ----------------------------------------------------------------------------

static void print_dos_header(IMAGE_DOS_HEADER *header)
{
	char s[MAX_MSG];

	output("DOS Header", NULL);

	snprintf(s, MAX_MSG, "%#x (MZ)", header->e_magic);
	output("Magic number", s);

	snprintf(s, MAX_MSG, "%d", header->e_cblp);
	output("Bytes in last page", s);

	snprintf(s, MAX_MSG, "%d", header->e_cp);
	output("Pages in file", s);

	snprintf(s, MAX_MSG, "%d", header->e_crlc);
	output("Relocations", s);

	snprintf(s, MAX_MSG, "%d", header->e_cparhdr);
	output("Size of header in paragraphs", s);

	snprintf(s, MAX_MSG, "%d", header->e_minalloc);
	output("Minimum extra paragraphs", s);

	snprintf(s, MAX_MSG, "%d", header->e_maxalloc);
	output("Maximum extra paragraphs", s);

	snprintf(s, MAX_MSG, "%#x", header->e_ss);
	output("Initial (relative) SS value", s);

	snprintf(s, MAX_MSG, "%#x", header->e_sp);
	output("Initial SP value", s);

	snprintf(s, MAX_MSG, "%#x", header->e_ip);
	output("Initial IP value", s);

	snprintf(s, MAX_MSG, "%#x", header->e_cs);
	output("Initial (relative) CS value", s);

	snprintf(s, MAX_MSG, "%#x", header->e_lfarlc);
	output("Address of relocation table", s);

	snprintf(s, MAX_MSG, "%#x", header->e_ovno);
	output("Overlay number", s);

	snprintf(s, MAX_MSG, "%#x", header->e_oemid);
	output("OEM identifier", s);

	snprintf(s, MAX_MSG, "%#x", header->e_oeminfo);
	output("OEM information", s);

	snprintf(s, MAX_MSG, "%#x", header->e_lfanew);
	output("PE header offset", s);
}

// ----------------------------------------------------------------------------

struct shell_ctx;

// Functions must return a value:
//  < 0	- To indicate an error.
//	0	- To indicate nothing was done.
//	> 0 - To indicate something was done.
typedef int (* cmd_func_t)(struct shell_ctx *ctx, const char *argument);

typedef struct cmd {
	const char *name;				// Name of the function
	cmd_func_t func;				// A pointer to the function to be executed
	const struct frame *frame;			// To which frame it belongs (generated during runtime)
	const char *desc;				// Description of what the function does
} cmd_t;

typedef struct frame {
	const char *name;					// Name of this frame
	const cmd_t *cmds;					// Sub-commands
	const struct frame *parent_frame;	// Parent frame
} frame_t;

typedef struct shell_ctx {
	pe_ctx_t *pe_ctx;
	options_t *options;
	char prompt[100];
	const frame_t *current_frame;
	cmd_t *current_cmd;
} shell_ctx_t;

static const frame_t g_root_frame;
static const frame_t g_dos_frame;
static const frame_t g_coff_frame;

int func_help(struct shell_ctx *ctx, const char *argument) {
	printf("TODO: HELP TEXT\n");
	return 1; // Success
}

int func_dotdot(struct shell_ctx *ctx, const char *argument) {
#if 0
	printf("ctx->current_frame = %p\n", ctx->current_frame);
	if (ctx->current_frame != NULL) {
		printf("ctx->current_frame->name = %s\n", ctx->current_frame->name);
		printf("ctx->current_frame->parent_frame %p\n", ctx->current_frame->parent_frame);
		if (ctx->current_frame->parent_frame != NULL)
			printf("ctx->current_frame->parent_frame->name %s\n", ctx->current_frame->parent_frame->name);
	}
#endif
	if (ctx->current_frame == NULL || ctx->current_frame->parent_frame == NULL)
		return 0;

	ctx->current_frame = ctx->current_frame->parent_frame;

	char *dot = strrchr(ctx->prompt, '.');
	if (dot == NULL)
		return 0;
	*dot = '\0';

	return 1;
}

int func_unload(struct shell_ctx *ctx, const char *argument) {
	if (!pe_is_loaded(ctx->pe_ctx)) {
		//fprintf(stdout, "No files loaded.");
		return 0; // Nothing was done.
	}

	fprintf(stdout, "Unloading '%s'\n", ctx->pe_ctx->path);
	pe_err_e err = pe_unload(ctx->pe_ctx);
	if (err != LIBPE_E_OK) {
		pe_error_print(stderr, err);
		return -1;
	}
	fprintf(stdout, "File unloaded.\n");

	return 1; // Success
}

int func_load(struct shell_ctx *ctx, const char *argument) {
	int ret = func_unload(ctx, NULL);
	if (ret < 0)
		return ret; // Error

	const char *path = argument;

	if (argument == NULL) {
		fprintf(stdout, "load <filename>\n");
		return 0; // Nothing was done.
	}

	fprintf(stdout, "Loading '%s'\n", path);

	pe_err_e err = pe_load_file(ctx->pe_ctx, path);
	if (err != LIBPE_E_OK) {
		pe_error_print(stderr, err);
		return -2; // Error
	}

	err = pe_parse(ctx->pe_ctx);
	if (err != LIBPE_E_OK) {
		pe_error_print(stderr, err);
		return -3; // Error
	}

	if (!pe_is_pe(ctx->pe_ctx)) {
		fprintf(stderr, "not a valid PE file\n");
		return -4; // Error
	}

	fprintf(stdout, "File loaded.\n");

	return 1; // Success
}

int func_exit(struct shell_ctx *ctx, const char *argument) {
	ctx->options->is_exiting = true;
	return 1;
}

int func_quit(struct shell_ctx *ctx, const char *argument) {
	ctx->options->is_exiting = true;
	return 1;
}

int func_dos(struct shell_ctx *ctx, const char *argument) {
	ctx->current_frame = &g_dos_frame;
	strlcat(ctx->prompt, ".", sizeof(ctx->prompt));
	strlcat(ctx->prompt, ctx->current_frame->name, sizeof(ctx->prompt));
	return 1;
}

int func_dos_print(struct shell_ctx *ctx, const char *argument) {
	if (!pe_is_loaded(ctx->pe_ctx)) {
		fprintf(stderr, "No files loaded.\n");
		return 0;
	}
	IMAGE_DOS_HEADER *header_ptr = pe_dos(ctx->pe_ctx);
	if (header_ptr == NULL) {
		fprintf(stderr, "The DOS header was not found. Invalid PE?\n");
		return -1;
	}
	print_dos_header(header_ptr);
	return 1;
}

int func_coff(struct shell_ctx *ctx, const char *argument) {
	ctx->current_frame = &g_coff_frame;
	strlcat(ctx->prompt, ".", sizeof(ctx->prompt));
	strlcat(ctx->prompt, ctx->current_frame->name, sizeof(ctx->prompt));
	return 1;
}

int func_coff_print(struct shell_ctx *ctx, const char *argument) {
	if (!pe_is_loaded(ctx->pe_ctx)) {
		fprintf(stderr, "No files loaded.\n");
		return 0;
	}
	IMAGE_COFF_HEADER *header_ptr = pe_coff(ctx->pe_ctx);
	if (header_ptr == NULL) {
		fprintf(stderr, "The COFF header was not found. Invalid PE?\n");
		return -1;
	}
	printf("TODO: print COFF header\n");
	return 1;
}

// ----------------------------------------------------------------------------

static const cmd_t g_dos_cmds[] = {
	{	"..",		func_dotdot,		NULL, "Navigate to parent." },
	{	"exit",		func_exit,			NULL, "Exit." },
	{	"q",		func_quit,			NULL, "Quit." },
	{	"quit",		func_quit,			NULL, "Quit." },
	{	"print",	func_dos_print,		NULL, "Print header." },
	{ 	NULL, 		NULL, 				NULL, NULL }
};

static const cmd_t g_coff_cmds[] = {
	{	"..",		func_dotdot,		NULL, "Navigate to parent." },
	{	"exit",		func_exit,			NULL, "Exit." },
	{	"q",		func_quit,			NULL, "Quit." },
	{	"quit",		func_quit,			NULL, "Quit." },
	{	"print",	func_coff_print,	NULL, "Print header." },
	{ 	NULL, 		NULL, 				NULL, NULL }
};

static const cmd_t g_root_cmds[] = {
	{	"?",		func_help,			NULL, "Print help." },
	{	"exit",		func_exit,			NULL, "Exit." },
	{	"q",		func_quit,			NULL, "Quit." },
	{	"quit",		func_quit,			NULL, "Quit." },
	{	"help",		func_help,			NULL, "Print help." },
	{	"load",		func_load,			NULL, "Load a PE into memory for further analysis." },
	{	"dos",		func_dos,			NULL, "Navigate to DOS." },
	{	"coff",		func_coff,			NULL, "Navigate to COFF." },
	{	"unload",	func_unload,		NULL, "Unload a PE from memory." },
	{ 	NULL, 		NULL, 				NULL, NULL }
};

static const frame_t g_root_frame	= { "root",	g_root_cmds,	NULL };
static const frame_t g_dos_frame	= { "dos",	g_dos_cmds,		&g_root_frame };
static const frame_t g_coff_frame	= { "coff",	g_coff_cmds,	&g_root_frame };

// ----------------------------------------------------------------------------

const cmd_t *find_command(shell_ctx_t *ctx, const char *name) {
	const cmd_t *commands = ctx->current_frame->cmds;
	if (commands == NULL)
		return NULL;

	for (int i = 0; commands[i].name != NULL; ++i) {
		if (strcmp(name, commands[i].name) == 0)
		return &commands[i];
	}

	return NULL;
}

shell_ctx_t *g_shell_ctx;

// Generator function for command completion.  STATE lets us know whether
// to start from scratch; without any state (i.e. STATE == 0), then we
// start at the top of the list.
char *command_generator(const char *text, int state) {
	static int list_index, len;

	// If this is a new word to complete, initialize now.  This includes
	// saving the length of TEXT for efficiency, and initializing the index
	// variable to 0.
	if (state == 0) {
		list_index = 0;
		len = strlen(text);
	}

	const frame_t *frame = g_shell_ctx->current_frame;
	const char *name;

	// Return the next name which partially matches from the command list.
	while ((name = frame->cmds[list_index].name) != NULL) {
		list_index++;

		if (strncmp(name, text, len) == 0)
			return strdup(name);
	}

	// If no names matched, then return NULL.
	return NULL;
}

// Attempt to complete on the contents of TEXT.  START and END show the
// region of TEXT that contains the word to complete.  We can use the
// entire line in case we want to do some simple parsing.  Return the
// array of matches, or NULL if there aren't any.
char **fileman_completion(char *text, int start, int end) {
	char **matches = NULL;

	// If this word is at the start of the line, then it is a command
	// to complete.  Otherwise it is the name of a file in the current
	// directory.
	if (start == 0)
		matches = completion_matches(text, command_generator);

	return matches;
}

// ----------------------------------------------------------------------------

// Tell the GNU Readline library how to complete.  We want to try to complete
// on command names if this is the first word in the line, or on filenames
// if not.
void initialize_readline() {
	// Allow conditional parsing of the ~/.inputrc file.
 	rl_readline_name = PROGRAM;

	// Tell the completer that we want a crack first.
	rl_attempted_completion_function = (CPPFunction *)fileman_completion;

	// Configure readline to auto-complete paths when the tab key is hit.
	//rl_bind_key('\t', rl_complete);
	// Disable auto-complete.
	//rl_bind_key('\t', rl_insert);
}

int execute_command(shell_ctx_t *shell_ctx, const char *line) {
	static const char delimiters[] = " ";
	char *mutable_line = strdup(line); // TODO(jweyrich): Verify if it succeeded
	char *saved_ptr;
	char *unknown_cmd = NULL;

	const char *command_name = strtok_r(mutable_line, delimiters, &saved_ptr);
	if (command_name == NULL) {
		fprintf(stderr, "Unknown command: %s\n", mutable_line);
		free(mutable_line);
		return 0;
	}

	// First command?
	if (shell_ctx->current_frame == NULL)
		shell_ctx->current_frame = &g_root_frame;

	const char *arguments = saved_ptr;
	const cmd_t *command = find_command(shell_ctx, command_name);
	if (command == NULL) {
		fprintf(stderr, "Unknown command: %s\n", command_name);
		free(mutable_line);
		return 0;
	}

	if (mutable_line != NULL)
		free(mutable_line);

	// First command?
	if (shell_ctx->current_cmd == NULL)
		shell_ctx->current_cmd = (cmd_t *)command;

	// Tell the command it belongs to the current frame.
	shell_ctx->current_cmd->frame = shell_ctx->current_frame;

	const int ret = command->func(shell_ctx, arguments);
	return ret;
}

static int my_add_history(const char *entry) {
	const int num_entries = entry != NULL ? 1 : 0;
	if (num_entries > 0)
		add_history(entry);

	wordexp_t exp_result;
	wordexp(HISTORY_FILE, &exp_result, 0);
	const char *path = exp_result.we_wordv[0];

#ifdef __APPLE__
	// Apple's libedit lacks append_history()
	int ret = write_history(path);
	if (ret != 0) {
		perror("write_history");
		return -1;
	}
#else
	int ret = append_history(num_entries, path);
	if (ret != 0) {
		perror("append_history");
		return -1;
	}
#endif

	return 0;
}

static int my_load_history(void) {
	wordexp_t exp_result;
	wordexp(HISTORY_FILE, &exp_result, 0);
	const char *path = exp_result.we_wordv[0];

	//printf("path = %s\n", path);

	// Check the history file to see if it exists and is accessible.
	int ret = access(path, R_OK|W_OK);
	if (ret == -1 && errno != ENOENT) {
		perror("access");
		return -1;
	}

	// Create HISTORY_FILE if it does not exist.
	if (errno == ENOENT) {
		my_add_history(NULL);
	} else {
		// Load contents of HISTORY_FILE.
		ret = read_history(path);
		if (ret != 0) {
			perror("read_history");
			ret = unlink(path);
			if (ret != 0) {
				perror("unlink");
				return -2;
			}
			ret = my_add_history(NULL);
			if (ret != 0) {
				return -3;
			}
		}
	}

	return 0;
}

// ----------------------------------------------------------------------------

int main(int argc, char *argv[])
{
	int ret;
	options_t *options = parse_options(argc, argv); // opcoes
	
	pe_ctx_t ctx;
	memset(&ctx, 0, sizeof(ctx));

	shell_ctx_t shell_ctx;
	memset(&shell_ctx, 0, sizeof(shell_ctx));
	g_shell_ctx = &shell_ctx; // REQUIRED by auto-completion.

	// Fill shell context.
	shell_ctx.pe_ctx = &ctx;
	shell_ctx.options = options;

	if (argc >= 2) {
		const char *path = argv[argc - 1];
		pe_err_e err = pe_load_file(shell_ctx.pe_ctx, path);
		if (err != LIBPE_E_OK) {
			pe_error_print(stderr, err);
			return EXIT_FAILURE;
		}

		err = pe_parse(shell_ctx.pe_ctx);
		if (err != LIBPE_E_OK) {
			pe_error_print(stderr, err);
			return EXIT_FAILURE;
		}

		if (!pe_is_pe(shell_ctx.pe_ctx))
			EXIT_ERROR("not a valid PE file");
	}

	initialize_readline(); // Warm-up our code-completion.

	// Read history
	ret = my_load_history();
	if (ret < 0)
		return EXIT_FAILURE;

	snprintf(shell_ctx.prompt, sizeof(shell_ctx.prompt), PROGRAM);

	while (!options->is_exiting) {
		char prompt[100];
		snprintf(prompt, sizeof(prompt), "%s> ", shell_ctx.prompt);

		const char *line = readline(prompt);

		// EOF?
		if (line == NULL)
			break;

		const char *trimmed_line = str_trim(line, strlen(line), STR_TRIM_LEFT_AND_RIGHT);
		free((char *)line);
		line = NULL;

		// The user gave us just empty space.
		if (trimmed_line[0] == '\0') {
			free((char *)trimmed_line);
			trimmed_line = NULL;
			continue;
		}

		int ret = execute_command(&shell_ctx, trimmed_line);
		if (ret < 0) {
			free((char *)trimmed_line);
			trimmed_line = NULL;
			//fprintf(stderr, "Oops! An error occurred...\n");
			continue;
		}

 		// Add to history.
		ret = my_add_history(trimmed_line);
		if (ret < 0) {
			// do nothing?
		}

		free((char *)trimmed_line);
		trimmed_line = NULL;
	}

	ret = func_unload(&shell_ctx, NULL);
	if (ret < 0)
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

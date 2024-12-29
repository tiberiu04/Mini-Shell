// SPDX-License-Identifier: BSD-3-Clause
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#include "cmd.h"
#include "utils.h"

#define READ            0
#define WRITE           1

void free_argv(char **argv)
{
	// Freeing the array of arguments
	if (!argv)
		return;
	for (int i = 0; argv[i] != NULL; i++)
		free(argv[i]);

	free(argv);
}

static int shell_exit(void)
{
	return SHELL_EXIT;
}

static bool shell_cd(word_t *dir)
{
	if (!dir) {
		// Changing to home directory
		char *home = getenv("HOME");

		// If HOME is not set, we cannot change to home directory
		if (!home) {
			fprintf(stderr, "no such file or directory\n");
			return false;
		}
		if (chdir(home) == -1) {
			fprintf(stderr, "no such file or directory\n");
			return false;
		}
		return true;
	}

	// Only one directory should is good
	if (dir->next_word != NULL)
		return false;

	// Changing to the specified directory
	char *path = get_word(dir);

	// If the directory does not exist, an error message will be displayed
	if (chdir(path) == -1) {
		fprintf(stderr, "no such file or directory\n");
		free(path);
		return false;
	}
	free(path);
	return true;
}

static bool redirect_fd(int filedes, const char *filename, int flags)
{
	// Opening the file with the appropriate mode and permissions
	int fd = open(filename, flags, 0666);

	if (fd < 0) {
		perror(filename);
		return false;
	}

	if (dup2(fd, filedes) < 0) {
		perror("dup2");
		close(fd);
		return false;
	}

	close(fd);
	return true;
}

static int apply_io_flags(simple_command_t *s, bool is_error)
{
	int flags = O_WRONLY | O_CREAT;

	// Error redirection
	if (is_error) {
		// If the error redirection is combined with the output redirection
		if (s->io_flags & IO_ERR_APPEND)
			flags |= O_APPEND;
		else
			flags |= O_TRUNC;
	} else {
		// Output redirection
		if (s->io_flags & IO_OUT_APPEND)
			flags |= O_APPEND;
		else
			flags |= O_TRUNC;
	}
	return flags;
}

static bool handle_redirections(simple_command_t *s)
{
	// out and err are the same file
	if (s->out && s->err) {
		char *out_filename = get_word(s->out);
		char *err_filename = get_word(s->err);

		// Checking if the filenames are identical
		if (out_filename && err_filename && strcmp(out_filename, err_filename) == 0) {
			int flags = O_WRONLY | O_CREAT;

			if ((s->io_flags & IO_OUT_APPEND) || (s->io_flags & IO_ERR_APPEND))
				flags |= O_APPEND;
			else
				flags |= O_TRUNC;

			// Opening the file with the appropriate mode and permissions
			int fd = open(out_filename, flags, 0666);

			if (fd < 0) {
				perror(out_filename);
				free(out_filename);
				free(err_filename);
				return false;
			}

			// Redirecting the file descriptors
			if (dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0) {
				perror("dup2");
				close(fd);
				free(out_filename);
				free(err_filename);
				return false;
			}
			close(fd);

			free(out_filename);
			free(err_filename);

			// Input redirection
			if (s->in) {
				char *in_filename = get_word(s->in);

				if (!in_filename || strlen(in_filename) == 0) {
					fprintf(stderr, "Redirection error: empty input filename\n");
					free(in_filename);
					return false;
				}

				if (!redirect_fd(STDIN_FILENO, in_filename, O_RDONLY)) {
					free(in_filename);
					return false;
				}
				free(in_filename);
			}

			return true;
		}

		free(out_filename);
		free(err_filename);
	}

	// Input redirection
	if (s->in) {
		char *filename = get_word(s->in);

		if (!filename || strlen(filename) == 0) {
			fprintf(stderr, "Redirection error: empty input filename\n");
			free(filename);
			return false;
		}

		if (!redirect_fd(STDIN_FILENO, filename, O_RDONLY)) {
			free(filename);
			return false;
		}

		free(filename);
	}

	// Output redirection
	if (s->out) {
		char *filename = get_word(s->out);

		if (!filename || strlen(filename) == 0) {
			fprintf(stderr, "Redirection error: empty output filename\n");
			free(filename);
			return false;
		}

		int flags = apply_io_flags(s, false);

		if (!redirect_fd(STDOUT_FILENO, filename, flags)) {
			free(filename);
			return false;
		}

		free(filename);
	}

	// Error redirection
	if (s->err) {
		char *filename = get_word(s->err);

		if (!filename || strlen(filename) == 0) {
			fprintf(stderr, "Redirection error: empty error filename\n");
			free(filename);
			return false;
		}

		int flags = apply_io_flags(s, true); // stderr

		if (!redirect_fd(STDERR_FILENO, filename, flags)) {
			free(filename);
			return false;
		}

		free(filename);
	}

	return true;
}

static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	if (!s || !s->verb)
		return 0;

	char *commandVerb = get_word(s->verb);

	if (!commandVerb)
		return 0;

	char *equal_ptr = strchr(commandVerb, '=');

	if (equal_ptr && s->params == NULL) {
		// Environment variable
		*equal_ptr = '\0';
		char *varname = commandVerb;
		char *varvalue = equal_ptr + 1;

		if (!handle_redirections(s)) {
			free(commandVerb);
			return 1;
		}

		// Setting the environment variable
		setenv(varname, varvalue, 1);
		free(commandVerb);
		return 0;
	}

	// Built-in cd
	if (strcmp(commandVerb, "cd") == 0) {
		// Saving the current file descriptors
		int savedStdin = dup(STDIN_FILENO);
		int savedStdout = dup(STDOUT_FILENO);
		int savedStderr = dup(STDERR_FILENO);

		if (s->in || s->out || s->err) {
			if (!handle_redirections(s)) {
				// Restoring the original standard input, output,
				// and error file descriptors
				dup2(savedStdin, STDIN_FILENO);
				dup2(savedStdout, STDOUT_FILENO);
				dup2(savedStderr, STDERR_FILENO);

				close(savedStdin);
				close(savedStdout);
				close(savedStderr);

				free(commandVerb);
				return 1;
			}
		}

		// Executing the 'cd' command and store its result
		int cdResult = shell_cd(s->params) ? 0 : 1;

		// Restoring the original standard input, output,
		// and error file descriptors
		dup2(savedStdin, STDIN_FILENO);
		dup2(savedStdout, STDOUT_FILENO);
		dup2(savedStderr, STDERR_FILENO);

		close(savedStdin);
		close(savedStdout);
		close(savedStderr);

		free(commandVerb);
		return cdResult;
	}

	// Built-in: exit, quit
	if (strcmp(commandVerb, "exit") == 0 || strcmp(commandVerb, "quit") == 0) {
		if (!handle_redirections(s)) {
			free(commandVerb);
			return 1;
		}
		free(commandVerb);
		return shell_exit();
	}

	// External command
	int commandArgc;
	char **commandArgv = get_argv(s, &commandArgc);

	pid_t pid = fork();

	if (pid < 0) {
		perror("fork");
		free(commandVerb);
		free_argv(commandArgv);
		return 1;
	}

	// Process
	if (pid == 0) {
		if (!handle_redirections(s)) {
			free(commandVerb);
			free_argv(commandArgv);
			exit(1);
		}

		// Executing the command
		execvp(commandVerb, commandArgv);
		// Error handling
		fprintf(stderr, "Execution failed for '%s'\n", commandVerb);
		free(commandVerb);
		free_argv(commandArgv);
		exit(127);
	}

	// Parent process
	int status;

	// Waiting for the process to finish
	waitpid(pid, &status, 0);

	free(commandVerb);
	free_argv(commandArgv);

	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	else
		return 1;
}

static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level, command_t *father)
{
	pid_t pid1 = fork();

	// Error handling
	if (pid1 < 0) {
		perror("fork");
		return false;
	}

	// Parsing the first command
	if (pid1 == 0) {
		int ret = parse_command(cmd1, level + 1, father);

		exit(ret);
	}

	pid_t pid2 = fork();

	// Error handling
	if (pid2 < 0) {
		perror("fork");
		int status;

		waitpid(pid1, &status, 0);
		return false;
	}

	if (pid2 == 0) {
		int ret = parse_command(cmd2, level + 1, father);

		exit(ret);
	}

	int status1, status2;

	// Waiting for the child processes to finish
	waitpid(pid1, &status1, 0);
	waitpid(pid2, &status2, 0);

	// Checking if both processes exited successfully
	return (WIFEXITED(status1) && WEXITSTATUS(status1) == 0 &&
			WIFEXITED(status2) && WEXITSTATUS(status2) == 0);
}

static bool create_pipe(int pipefd[2])
{
	// Creating the pipe
	if (pipe(pipefd) < 0) {
		perror("pipe");
		return false;
	}
	return true;
}

static bool check_error(int pipefd[2], pid_t pid, int which_pid)
{
	if (pid < 0) {
		perror("fork");
		close(pipefd[0]);
		close(pipefd[1]);
		// Waiting for the other process to finish
		if (which_pid == 1) {
			int status;

			waitpid(pid, &status, 0);
		}

		return false;
	}

	return true;
}

void execute(int pipefd[2], pid_t pid, command_t *cmd, int level, command_t *father,
			 int which_pid)
{
	if (pid == 0) {
		// closing the process
		close(pipefd[which_pid]);
		// checking if the process is the first or the second
		if (!which_pid)
			dup2(pipefd[1], STDOUT_FILENO);
		else
			dup2(pipefd[0], STDIN_FILENO);
		close(pipefd[!which_pid]);
		// parsing the command
		int ret = parse_command(cmd, level + 1, father);

		exit(ret);
	}
}

static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level, command_t *father)
{
	int pipefd[2];

	if (!create_pipe(pipefd))
		return false;

	// Forking the first process
	pid_t pid1 = fork();

	// Error handling
	if (!check_error(pipefd, pid1, 0))
		return false;

	// Process 1
	execute(pipefd, pid1, cmd1, level, father, 0);

	pid_t pid2 = fork();

	if (!check_error(pipefd, pid2, 1))
		return false;

	// Process 2
	execute(pipefd, pid2, cmd2, level, father, 1);

	for (int i = 0; i < 2; i++)
		close(pipefd[i]);

	int status1, status2;

	// Waiting for the processes to finish
	waitpid(pid1, &status1, 0);
	waitpid(pid2, &status2, 0);

	return (WIFEXITED(status2) && WEXITSTATUS(status2) == 0);
}

int parse_command(command_t *c, int level, command_t *father)
{
	if (!c)
		return 0;

	if (c->op == OP_NONE)
		return parse_simple(c->scmd, level, father);

	int ret1 = 0, ret2 = 0;

	switch (c->op) {
	case OP_SEQUENTIAL:
		ret1 = parse_command(c->cmd1, level + 1, c);
		ret2 = parse_command(c->cmd2, level + 1, c);
		return ret2;

	case OP_PARALLEL:
		return run_in_parallel(c->cmd1, c->cmd2, level, c) ? 0 : 1;

	case OP_CONDITIONAL_ZERO:
		ret1 = parse_command(c->cmd1, level + 1, c);
		if (ret1 == 0)
			ret2 = parse_command(c->cmd2, level + 1, c);
		else
			ret2 = ret1;
		return ret2;

	case OP_CONDITIONAL_NZERO:
		ret1 = parse_command(c->cmd1, level + 1, c);
		if (ret1 != 0)
			ret2 = parse_command(c->cmd2, level + 1, c);
		else
			ret2 = ret1;
		return ret2;

	case OP_PIPE:
		return run_on_pipe(c->cmd1, c->cmd2, level, c) ? 0 : 1;

	default:
		return SHELL_EXIT;
	}
}

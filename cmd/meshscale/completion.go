package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

func init() {
	register(&command{name: "completion", short: "generate bash, zsh or fish shell completion", run: func(_ context.Context, args []string) error {
		if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
			fmt.Println("usage: meshscale completion bash|zsh|fish")
			return nil
		}
		if len(args) != 1 {
			return fmt.Errorf("usage: meshscale completion bash|zsh|fish")
		}
		return writeCompletion(os.Stdout, args[0])
	}})
}

// Read the same registry used by help at invocation time, after every init.
func writeCompletion(out io.Writer, shell string) error {
	var names []string
	for name := range commands {
		names = append(names, name)
	}
	sort.Strings(names)
	var script string
	switch shell {
	case "bash":
		script = "_meshscale() {\n  if [[ $COMP_CWORD == 1 ]]; then\n    COMPREPLY=( $(compgen -W '" + strings.Join(names, " ") + "' -- \"${COMP_WORDS[COMP_CWORD]}\") )\n  fi\n}\ncomplete -F _meshscale meshscale\n"
	case "zsh":
		script = "#compdef meshscale\n_meshscale() {\n  local -a commands\n  commands=(\n"
		for _, name := range names {
			script += "    '" + name + ":" + strings.ReplaceAll(commands[name].short, "'", "'\\''") + "'\n"
		}
		script += "  )\n  _describe 'command' commands\n}\ncompdef _meshscale meshscale\n"
	case "fish":
		script = "complete -c meshscale -f\n"
		for _, name := range names {
			script += "complete -c meshscale -n '__fish_use_subcommand' -a '" + name + "' -d '" + strings.ReplaceAll(commands[name].short, "'", "\\'") + "'\n"
		}
	default:
		return fmt.Errorf("unsupported shell %q; choose bash, zsh or fish", shell)
	}
	_, err := io.WriteString(out, script)
	return err
}

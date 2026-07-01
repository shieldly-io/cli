const BASH_COMPLETION = `
_shieldly() {
  local cur prev words cword
  _init_completion || return

  local commands="analyze-iam analyze-cf api-keys completion"
  local global_opts="--api-key --help -h --version -v"

  case $prev in
    analyze-iam)
      if [[ $cur == -* ]]; then
        COMPREPLY=($(compgen -W "--type --format --api-key --help -h" -- "$cur"))
      else
        COMPREPLY=($(compgen -f -- "$cur"))
      fi
      return
      ;;
    analyze-cf)
      if [[ $cur == -* ]]; then
        COMPREPLY=($(compgen -W "--format --api-key --help -h" -- "$cur"))
      else
        COMPREPLY=($(compgen -f -- "$cur"))
      fi
      return
      ;;
    api-keys)
      COMPREPLY=($(compgen -W "list create revoke" -- "$cur"))
      return
      ;;
    completion)
      COMPREPLY=($(compgen -W "bash zsh install" -- "$cur"))
      return
      ;;
    --type)
      COMPREPLY=($(compgen -W "identity cross_account" -- "$cur"))
      return
      ;;
    --format)
      COMPREPLY=($(compgen -W "table json" -- "$cur"))
      return
      ;;
    --label)
      return
      ;;
    --scopes)
      COMPREPLY=($(compgen -W "iam cf cost" -- "$cur"))
      return
      ;;
    --api-key)
      return
      ;;
  esac

  if [[ $cur == -* ]]; then
    COMPREPLY=($(compgen -W "$global_opts" -- "$cur"))
  elif [[ $cword -eq 1 ]]; then
    COMPREPLY=($(compgen -W "$commands" -- "$cur"))
  fi
} &&
  complete -F _shieldly shieldly
`;

const ZSH_COMPLETION = `
#compdef shieldly

_shieldly() {
  local -a opts
  local curcontext="$curcontext" state line ret=1

  _arguments -C \
    '(-h --help)'{-h,--help}'[Show help]' \
    '(-v --version)'{-v,--version}'[Show version]' \
    '--api-key[API key]:api key' \
    '1: :->command' \
    '*: :->args' \
    && ret=0

  case $state in
    command)
      local commands; commands=(
        'analyze-iam:Analyze an IAM policy for security issues'
        'analyze-cf:Analyze a CloudFormation template'
        'api-keys:Manage API keys'
        'completion:Generate shell completion script'
      )
      _describe 'command' commands && ret=0
      ;;
    args)
      case $words[1] in
        analyze-iam)
          _arguments \
            '--type[Policy type]:type:(identity cross_account)' \
            '--format[Output format]:format:(table json)' \
            '--api-key[API key]:api key' \
            '(-h --help)'{-h,--help}'[Show help]' \
            '*:policy file:_files' \
            && ret=0
          ;;
        analyze-cf)
          _arguments \
            '--format[Output format]:format:(table json)' \
            '--api-key[API key]:api key' \
            '(-h --help)'{-h,--help}'[Show help]' \
            '*:template file:_files' \
            && ret=0
          ;;
        api-keys)
          _arguments \
            '--format[Output format]:format:(table json)' \
            '--api-key[API key]:api key' \
            '1: :->subcommand' \
            '*: :->args' \
            && ret=0
          case $state in
            subcommand)
              local subcommands; subcommands=(
                'list:List all API keys'
                'create:Create a new API key'
                'revoke:Revoke an API key'
              )
              _describe 'subcommand' subcommands && ret=0
              ;;
            args)
              case $words[2] in
                create)
                  _arguments \
                    '--label[Key label]' \
                    '--scopes[Comma-separated scopes]:scopes:(iam cf cost)' \
                    && ret=0
                  ;;
                revoke)
                  _arguments '*:key id' && ret=0
                  ;;
              esac
              ;;
          esac
          ;;
        completion)
          _arguments \
            '1: :->shell' \
            && ret=0
          case $state in
            shell)
              local shells; shells=(
                'bash:Generate bash completion'
                'zsh:Generate zsh completion'
                'install:Install completion for current shell'
              )
              _describe 'shell' shells && ret=0
              ;;
          esac
          ;;
      esac
      ;;
  esac

  return ret
}

_shieldly
`;

const HELP = `
Usage: shieldly completion <shell>

Generate shell completion scripts for the shieldly CLI.

Shells:
  bash       Generate bash completion
  zsh        Generate zsh completion
  install    Auto-detect shell and install completion

Examples:
  eval "$(shieldly completion bash)"       # Source bash completion
  shieldly completion zsh > /usr/local/share/zsh/site-functions/_shieldly  # Install zsh completion
  shieldly completion install                # Auto-detect and install
`;

export async function completion(args) {
  if (!args.length || args.includes('-h') || args.includes('--help')) {
    console.log(HELP);
    return;
  }

  const shell = args[0];

  switch (shell) {
    case 'bash':
      console.log(BASH_COMPLETION.trimStart());
      break;
    case 'zsh':
      console.log(ZSH_COMPLETION.trimStart());
      break;
    case 'install':
      await installCompletion();
      break;
    default:
      console.error(`Unsupported shell: ${shell}`);
      console.log('Supported shells: bash, zsh');
      process.exit(1);
  }
}

async function installCompletion() {
  const shell = process.env.SHELL || '';
  const home = process.env.HOME || '';

  if (shell.includes('zsh')) {
    const dest = `${home}/.zshrc`;
    const line =
      '\n# shieldly CLI completion\nautoload -Uz compinit && compinit -C 2>/dev/null\neval "$(shieldly completion zsh)" 2>/dev/null';
    try {
      const { readFileSync, appendFileSync, existsSync } = await import('node:fs');
      if (existsSync(dest)) {
        const existing = readFileSync(dest, 'utf8');
        if (existing.includes('shieldly completion')) {
          console.log('shieldly completion already installed in ~/.zshrc');
          return;
        }
      }
      appendFileSync(dest, line);
      console.log('Installed shieldly completion in ~/.zshrc');
      console.log('Run: source ~/.zshrc');
    } catch (err) {
      console.error(`Failed to install: ${err.message}`);
      process.exit(1);
    }
  } else if (shell.includes('bash')) {
    const dest = `${home}/.bashrc`;
    const line =
      '\n# shieldly CLI completion\nsource /dev/stdin <<< "$(shieldly completion bash)" 2>/dev/null';
    try {
      const { readFileSync, appendFileSync, existsSync } = await import('node:fs');
      if (existsSync(dest)) {
        const existing = readFileSync(dest, 'utf8');
        if (existing.includes('shieldly completion')) {
          console.log('shieldly completion already installed in ~/.bashrc');
          return;
        }
      }
      appendFileSync(dest, line);
      console.log('Installed shieldly completion in ~/.bashrc');
      console.log('Run: source ~/.bashrc');
    } catch (err) {
      console.error(`Failed to install: ${err.message}`);
      process.exit(1);
    }
  } else {
    console.error(`Unsupported shell: ${shell}. Install manually:`);
    console.log('  eval "$(shieldly completion bash)"  # For bash');
    console.log('  eval "$(shieldly completion zsh)"   # For zsh');
    process.exit(1);
  }
}

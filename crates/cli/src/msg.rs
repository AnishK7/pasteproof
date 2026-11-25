//! All user-facing text lives here so it can be translated later.

pub const HELP: &str = "\
pasteproof - stops 'paste this command' (ClickFix) attacks before they run

USAGE
  pasteproof check [--json] [--pasted] -- '<command>'   Check a command (exit 0 allow, 1 caution, 2 danger)
  pasteproof check --stdin                              Check a command read from stdin
  pasteproof why -- '<command>'                         Explain every finding in detail
  pasteproof init bash|zsh                              Print the shell integration
  pasteproof allow add <https://origin | host>          Trust an installer's origin
  pasteproof allow list | remove <entry>                Show or remove trusted origins
  pasteproof rules                                      List detection rules
  pasteproof --version

SETUP
  bash:  echo 'eval \"$(pasteproof init bash)\"' >> ~/.bashrc
  zsh:   echo 'eval \"$(pasteproof init zsh)\"'  >> ~/.zshrc

Everything runs locally. Nothing is ever sent anywhere.
";

pub const DANGER_TITLE: &str = "STOP - this looks like a malware trick";
pub const CAUTION_TITLE: &str = "Check before running";
pub const WHAT_IT_DOES: &str = "What it does:";
pub const HIDDEN: &str = "Hidden or decoded content:";
pub const NEVER: &str = "Real websites never ask you to paste commands into a terminal to prove you're human or to fix an error.";
pub const DANGER_PROMPT: &str = "Type 'run' to run it anyway, or press Enter to cancel: ";
pub const CAUTION_PROMPT: &str = "Run it? [y/N] ";
pub const CANCELLED: &str = "Cancelled. Nothing was run.";
pub const ALLOW_TIP: &str = "Trust this site from now on:";
pub const NO_TTY: &str = "pasteproof: no terminal to ask you on; running the command (fail open).";
pub const SAFE: &str = "No risky patterns found.";

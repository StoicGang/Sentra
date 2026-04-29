"""
cli/commands/generator.py - password generation command.
Standalone genpass command — no vault unlock required.
"""
from __future__ import annotations

from cli.ui import print_error, print_success, print_info
from cli.colors import colors

DEFAULT_PASSWORD_LENGTH = 20


def cmd_genpass(cli, args):
    length = (args.length if args.length else DEFAULT_PASSWORD_LENGTH)
    if length < 8 or length > 128:
        print_error("Length must be between 8 and 128.")
        return
    try:
        pw, warning = cli.passgen.generate_password(length=length)
        print("\n" + colors.info("Generated Password:"))
        print("  " + colors.success(pw))

        score, label, _ = cli.passgen.calculate_strength(pw)
        if score < 30:
            strength_label = colors.error(label)
        elif score < 70:
            strength_label = colors.warning(label)
        else:
            strength_label = colors.success(label)
        print("  Strength: " + strength_label + " (" + str(score) + "/100)")

        if warning:
            print("  " + colors.warning("Note: " + warning))

        if getattr(args, "copy", False):
            from cli.commands.tools import cmd_copy
            cli._last_password_secret = pw
            cli._last_password_title = "Generated"
            cmd_copy(cli, None)
        else:
            print(colors.dim("  Tip: use --copy / -c to copy to clipboard"))
        print()
    except Exception as e:
        print_error("Password generation failed: " + str(e))

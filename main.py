import argparse
import logging
import subprocess
import os
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="Analyzes code for missing input sanitization vulnerabilities.")
    parser.add_argument("target", help="The target directory or file to analyze.")
    parser.add_argument("--tools", nargs="+", default=["bandit", "flake8", "pylint"],
                        help="List of tools to use for analysis (default: bandit flake8 pylint).  Available tools: bandit, flake8, pylint")
    parser.add_argument("--output", "-o", help="Output file to write results to.")
    parser.add_argument("--ignore", "-i", nargs="+", help="List of files or directories to ignore.")
    parser.add_argument("--offensive", action="store_true", help="Enable offensive security checks (e.g., SQL injection, command injection).")

    return parser


def run_tool(tool, target, ignore=None, output=None, offensive=False):
    """
    Runs a specified static analysis tool on the target.
    Args:
        tool (str): The name of the tool to run (e.g., bandit, flake8, pylint).
        target (str): The target directory or file to analyze.
        ignore (list, optional): List of files/directories to ignore. Defaults to None.
        output (str, optional): Output file to write results to. Defaults to None.
        offensive (bool, optional): Enable offensive security checks. Defaults to False.

    Returns:
        tuple: A tuple containing the return code and the output of the tool.
    """

    try:
        command = []
        if tool == "bandit":
            command = ["bandit", "-r", target, "-q"] # -q for quiet mode
            if offensive:
                command.extend(["-t", "B101,B301,B603,B605,B608"]) # Limit to the offensive checks with the include option (-t), not the skip option (-s).
            if ignore:
              for i in ignore:
                command.extend(["-x", i])
            if output:
              command.extend(["-o", output, "-f", "txt"])

        elif tool == "flake8":
            command = ["flake8", target]
            if ignore:
              command.extend(["--exclude", ",".join(ignore)])

            if output:
              command.extend(["--output-file", output])
        elif tool == "pylint":
            # Pylint has no check category called "security": passing
            # --enable=security made every pylint run abort with an
            # unknown-option-value error (exit 32) before linting anything.
            # The default checks run instead, with reports off.
            command = ["pylint", target, "--reports=n"]
            if ignore:
              command.extend(["--ignore", ",".join(ignore)])
            if output:
              command.extend(["--output", output])

        else:
            raise ValueError(f"Unsupported tool: {tool}")

        logging.info(f"Running: {' '.join(command)}")
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        return_code = process.returncode

        stdout_str = stdout.decode("utf-8", errors="ignore")
        stderr_str = stderr.decode("utf-8", errors="ignore")
        logging.debug(f"Tool output (stdout):\n{stdout_str}")
        logging.debug(f"Tool output (stderr):\n{stderr_str}")
        return return_code, stdout_str, stderr_str, False

    except FileNotFoundError as e:
        logging.error(f"Error: {tool} not found. Please ensure it is installed and in your PATH.")
        return 1, "", str(e), True
    except Exception as e:
        logging.error(f"An unexpected error occurred while running {tool}: {e}")
        return 1, "", str(e), True



def validate_target(target):
    """
    Validates that the target file or directory exists.
    Args:
        target (str): The path to the target file or directory.
    Returns:
        bool: True if the target exists, False otherwise.
    """
    if not os.path.exists(target):
        logging.error(f"Error: Target '{target}' does not exist.")
        return False
    return True


def validate_tools(tools):
    """
    Validates that the requested tools are valid.
    Args:
        tools (list): List of strings, representing the tools to use.
    Returns:
        bool: True if all tools are valid, False otherwise.
    """
    valid_tools = ["bandit", "flake8", "pylint"]
    for tool in tools:
        if tool not in valid_tools:
            logging.error(f"Error: Invalid tool '{tool}'. Valid tools are: {valid_tools}")
            return False
    return True

def validate_ignore_paths(ignore_paths):
    """
    Validates the ignore paths exist.
    Args:
        ignore_paths (list): List of filepaths to ignore.

    Returns:
        bool: True if all ignore paths are valid, False otherwise.
    """
    if ignore_paths is None:
        return True

    # I require every ignore path to exist. An ignore written for
    # a tree on another machine, or a simple typo, fails the whole
    # run before any tool starts, which is strict on purpose.
    for path in ignore_paths:
        if not os.path.exists(path):
            logging.error(f"Error: Ignore path '{path}' does not exist.")
            return False
    return True


def main():
    """
    Main function to parse arguments, validate inputs, run the analysis tools,
    and handle errors.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if not validate_target(args.target):
        sys.exit(1)

    if not validate_tools(args.tools):
        sys.exit(1)

    if args.ignore and not validate_ignore_paths(args.ignore):
        sys.exit(1)

    results = {}
    failed_tools = []
    for tool in args.tools:
        logging.info(f"Running {tool} on {args.target}...")
        # The combined output file belongs to main, not to each tool:
        # passing it down made every tool write the same path, and the
        # combined write afterwards overwrote whatever a tool had put there.
        return_code, stdout, stderr, failed_to_run = run_tool(tool, args.target, args.ignore, None, args.offensive)
        results[tool] = {"return_code": return_code, "stdout": stdout, "stderr": stderr}
        if failed_to_run:
            failed_tools.append(tool)

        # I warn on a non zero code and keep going. A tool that found
        # real problems and a tool that merely has findings both land
        # here, and neither one changes this program's own exit code.
        if return_code != 0:
            logging.warning(f"{tool} returned a non-zero exit code: {return_code}")
            if stderr:
                logging.error(f"{tool} stderr: {stderr}")

    # Output results (currently to console, could be to a file)
    if args.output:
        try:
            with open(args.output, "w") as f:
                for tool, result in results.items():
                    f.write(f"Results for {tool}:\n")
                    f.write(f"Return Code: {result['return_code']}\n")
                    f.write(f"Stdout:\n{result['stdout']}\n")
                    f.write(f"Stderr:\n{result['stderr']}\n")
                    f.write("-" * 40 + "\n")
            logging.info(f"Results written to {args.output}")
        except IOError as e:
            logging.error(f"Error writing to output file: {e}")
            sys.exit(1)
    else:
        for tool, result in results.items():
            print(f"Results for {tool}:")
            print(f"Return Code: {result['return_code']}")
            print(f"Stdout:\n{result['stdout']}")
            print(f"Stderr:\n{result['stderr']}")
            print("-" * 40)

    # Only a tool that could not run at all fails the run. That
    # split is the whole contract: findings are data for the
    # reader, a missing tool is a broken scan.
    if failed_tools:
        logging.error(f"Analysis incomplete: these tools were missing or failed to run: {', '.join(failed_tools)}")
        sys.exit(1)

    logging.info("Analysis complete.")


if __name__ == "__main__":
    main()
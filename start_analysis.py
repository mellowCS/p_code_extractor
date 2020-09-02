from pathlib import Path
import subprocess
import argparse

PLUGINS = 'plugins'

def start_analysis(command: list):
    try:
        subprocess.run(args=command, stderr=subprocess.STDOUT, cwd=str(Path.cwd()))
    except subprocess.CalledProcessError as err:
        print('Status : FAIL', err.returncode)


def build_command(ghidra: Path, import_: Path) -> list:
    ghidra = ghidra / 'support' / 'analyzeHeadless'
    project_root = Path.cwd()
    tmp = project_root / 'tmp'
    tmp.mkdir()
    command = [str(ghidra), str(tmp), 'PcodeExtractor', '-import', str(import_), '-postScript', 'PcodeExtractor.java', str(tmp / 'cwe_78_2.json'),  '-scriptPath', str(project_root), '-deleteProject']

    return command


def plugin_folder_exists(path: Path):
    plugin_path = path / PLUGINS
    if not plugin_path.is_dir():
        plugin_path.mkdir()

def is_in_classpath(location: Path, filename: str) -> bool:
    plugin_path = location / PLUGINS
    if list(plugin_path.glob('gson*.jar')):
        return True
    return False


def is_directory(parser: argparse.ArgumentParser, path: str) -> Path:
    dir = Path(path)
    if dir.is_dir() and 'ghidra' in path:
        return dir
    parser.error(f'Given Ghidra path {path} is not valid.')


def handle_gson(parser: argparse.ArgumentParser, path: str) -> Path:
    file = Path(path)
    if file.is_file():
        if 'gson' in path and file.suffix == '.jar':
            return file
        parser.error(f'Given file {path} is not a jar file or contains the name gson.')
    parser.error(f'Gson library could not be found at {path}.')


def is_file(parser: argparse.ArgumentParser, path: str) -> Path:
    file = Path(path)
    if file.is_file():
        return file
    parser.error(f'Binary could not be found at {path}.')


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('-n', '--gson', dest='gson', help='Path to Gson library required in Ghidra\'s classpath. Has to be set with the plugin parameter.',
    metavar='FILE', type=lambda f: handle_gson(parser, f))

    parser.add_argument('-g', '--ghidra', required=True, dest='ghidra', help='Path to Ghidra. Ends in .../ghidra_9.X.X_PUBLIC/.',
    metavar='PATH', type=lambda d: is_directory(parser, d))

    parser.add_argument('-p', '--plugin', dest="plugin", help='Path to ghidra\'s plugins directory where gson.jar should be placed. Ends in .../.ghidra/.ghidra_9.X.X_PUBLIC/. Has to be set with the gson parameter',
    metavar='PATH', type=lambda p: is_directory(parser, p))

    parser.add_argument('-i', '--import', required=True, dest='import_', help='Path to binary which is to be analysed by Ghidra.',
    metavar='FILE', type=lambda f: is_file(parser, f))

    args = parser.parse_args()

    # If a gson library is specified, the path to .../.ghidra/.ghidra_9.X.X_PUBLIC/ also needs to be specified
    if args.gson and not args.plugin or not args.gson and args.plugin:
        parser.error('--gson and --plugin have to be set together.')

    # check whether the plugins folder exist in .../.ghidra/.ghidra_9.X.X_PUBLIC/. If not, create it.
    if args.plugin:
        plugin_folder_exists(args.plugin)
        # check whether there already is a gson file in .../.ghidra/.ghidra_9.X.X_PUBLIC/plugins/
        if is_in_classpath(args.plugin, args.gson.name):
            print(f'\nGson lib {args.gson} already in Ghidra classpath.\n')
        else:
            # move the gson file from the specfied location to .../.ghidra/.ghidra_9.X.X_PUBLIC/plugins/
            args.gson.replace(args.plugin / PLUGINS / args.gson.name)

    return args


def main():
    args = parse_args()
    command = build_command(args.ghidra, args.import_)
    start_analysis(command=command)


if __name__ == '__main__':
    main()

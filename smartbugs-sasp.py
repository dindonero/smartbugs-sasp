import json
import os
import pathlib
import time
from multiprocessing import Pool
from multiprocessing.managers import BaseManager

from flask import Flask, request, send_from_directory

from smartbugs.smartBugs import analyse
from smartbugs.src.output_parser.SarifHolder import SarifHolder

DEBUG = True

CONFIG_TOOLS_PATH = 'smartbugs/config/tools'
RESULTS_FOLDER = 'results'
REPOS_FOLDER = 'repos'

app = Flask(__name__)


def secure_path_and_filename(full_path_filename):
    full_path_filename = full_path_filename.replace('\\', '/')
    while '../' in full_path_filename:
        full_path_filename = full_path_filename.replace('../', './')
    path = full_path_filename[:full_path_filename.rfind('/')]
    return path, full_path_filename


def save_file(full_path_filename, file):
    path, full_path_filename = secure_path_and_filename(full_path_filename)
    pathlib.Path(path).mkdir(parents=True, exist_ok=True)
    if full_path_filename.endswith('.sol'):
        file.save(full_path_filename)


# get tools available by parsing the name of the config files
def get_available_tools():
    return [os.path.splitext(f)[0] for f in os.listdir(CONFIG_TOOLS_PATH) if
            os.path.isfile(os.path.join(CONFIG_TOOLS_PATH, f))]


@app.route('/', methods=('GET', 'POST'))
def analyse_solidity_files():
    user_hash = request.form['user-hash']
    tools = request.form['tools'].split(',')
    processes = 1

    app.logger.debug('Receiving Request with - User-Hash: {}, Tools: {}'.format(user_hash, tools))

    results_user_path = RESULTS_FOLDER + '/user-' + user_hash + '/' + time.strftime("%Y%d%m_%H%M",
                                                                                    time.localtime()) + '/'
    repo_user_path = REPOS_FOLDER + '/user-' + user_hash + '/'

    # Save Received Files in user_path
    app.logger.debug('Files:')
    for filename, file in request.files.items():
        app.logger.debug(filename)
        save_file(repo_user_path + filename, file)

    # Gather All Files in User Repo
    files_to_analyze = []
    for root, dirs, files in os.walk(repo_user_path):
        for name in files:
            files_to_analyze.append(os.path.join(root, name))

    # Get and verify requested tools
    available_tools = get_available_tools()
    if 'all' in tools:
        tools = available_tools
    else:
        for tool in tools:
            if tool.lower() not in available_tools:
                app.logger.error('Requested tool not available. Tool: %s', tool)
                return 'Requested tool not available. Tool: {}'.format(tool), 404  # Http Bad Request

    BaseManager.register('SarifHolder', SarifHolder)
    manager = BaseManager()
    manager.start()
    sarif_holder = manager.SarifHolder()

    # Setup SmartBugs analysis
    tasks = []
    for file in files_to_analyze:
        for tool in tools:
            tasks.append((tool, file.replace('\\', '/'), sarif_holder, repo_user_path, results_user_path, DEBUG,
                          len(files_to_analyze) * len(tools)))  # SmartBugs V1 Output for Debug purposes
    pathlib.Path(results_user_path).mkdir(parents=True, exist_ok=True)

    # Run SmartBugs analysis
    # app.logger.debug('Starting SmartBugs run with Tasks: {}'.format(tasks))
    with Pool(processes=processes) as pool:
        pool.map(analyse, tasks)

    with open(results_user_path + 'results.sarif', 'w') as sarif_file:
        json.dump(sarif_holder.print(), sarif_file, indent=2)

    return send_from_directory(directory=results_user_path, filename='results.sarif', as_attachment=True)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=DEBUG)

#!/usr/bin/env python3

import argparse
import json
import os
import pathlib
import sys
from datetime import timedelta
from multiprocessing import Pool, Value, Manager
from time import time, localtime, strftime

import git

from smartbugs.src.docker_api.docker_api import analyse_files
from smartbugs.src.output_parser.SarifHolder import SarifHolder

output_folder = strftime("%Y%d%m_%H%M", localtime())
pathlib.Path('smartbugs/results/logs/').mkdir(parents=True, exist_ok=True)
logs = open('smartbugs/results/logs/SmartBugs_' + output_folder + '.log', 'w')
start_time = time()
nb_task_done = Value('i', 0)
total_execution = Value('f', 0)


def analyse(args):
    global logs, output_folder, nb_task_done, total_execution

    (tool, file, sarif_holder, import_path, output_folder, v1_output, nb_task) = args

    try:
        start = time()

        sys.stdout.write('\x1b[1;37m' + 'Analysing file [%d/%d]: ' % (nb_task_done.value, nb_task) + '\x1b[0m')
        sys.stdout.write('\x1b[1;34m' + file + '\x1b[0m')
        sys.stdout.write('\x1b[1;37m' + ' [' + tool + ']' + '\x1b[0m' + '\n')

        analyse_files(tool, file, logs, output_folder, sarif_holder, v1_output, import_path)

        with nb_task_done.get_lock():
            nb_task_done.value += 1

        with total_execution.get_lock():
            total_execution.value += time() - start

        duration = str(timedelta(seconds=round(time() - start)))

        task_sec = nb_task_done.value / (time() - start_time)
        remaining_time = str(timedelta(seconds=round((nb_task - nb_task_done.value) / task_sec)))

        sys.stdout.write(
            '\x1b[1;37m' + 'Done [%d/%d, %s]: ' % (nb_task_done.value, nb_task, remaining_time) + '\x1b[0m')
        sys.stdout.write('\x1b[1;34m' + file + '\x1b[0m')
        sys.stdout.write('\x1b[1;37m' + ' [' + tool + '] in ' + duration + ' ' + '\x1b[0m' + '\n')
        logs.write('[%d/%d] ' % (nb_task_done.value, nb_task) + file + ' [' + tool + '] in ' + duration + ' \n')
    except Exception as e:
        print(e)
        raise e

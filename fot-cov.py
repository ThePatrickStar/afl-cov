import argparse
import errno
import glob
import os
import re
import signal
import subprocess
import sys
import time

from shutil import rmtree
from sys import argv
from tempfile import NamedTemporaryFile

from utils import *

__version__ = '0.0.1'


def run_cmd(cmd, log_file, cargs, collect):
    out = []

    if cargs.verbose:
        if log_file:
            logr("    CMD: %s" % cmd, log_file, cargs)
        else:
            print("    CMD: %s" % cmd)

    fh = None
    if cargs.disable_cmd_redirection or collect == WANT_OUTPUT \
            or collect == LOG_ERRORS:
        fh = NamedTemporaryFile(delete=False)
    else:
        fh = open(os.devnull, 'w')

    es = subprocess.call(cmd, stdin=None,
                         stdout=fh, stderr=subprocess.STDOUT, shell=True)

    fh.close()

    if cargs.disable_cmd_redirection or collect == WANT_OUTPUT \
            or collect == LOG_ERRORS:
        with open(fh.name, 'r') as f:
            for line in f:
                out.append(line.rstrip('\n'))
        os.unlink(fh.name)

    if (es != 0) and (collect == LOG_ERRORS):
        if log_file:
            logr("    Non-zero exit status '%d' for CMD: %s" % (es, cmd),
                 log_file, cargs)
        else:
            print("    Non-zero exit status '%d' for CMD: %s" % (es, cmd))

    return es, out


def is_dir(dpath):
    return os.path.exists(dpath) and os.path.isdir(dpath)


def mkdirs(cov_paths, cargs):
    create_cov_dirs = False
    if is_dir(cov_paths['top_dir']):
        if cargs.overwrite:
            rmtree(cov_paths['top_dir'])
            create_cov_dirs = True
    else:
        create_cov_dirs = True

    if create_cov_dirs:
        for k in ['top_dir', 'web_dir', 'lcov_dir', 'diff_dir']:
            if not is_dir(cov_paths[k]):
                os.mkdir(cov_paths[k])

        # write coverage results in the following format
        cfile = open(cov_paths['id_delta_cov'], 'w')
        if cargs.cover_corpus or cargs.coverage_at_exit:
            cfile.write("# id:[range]..., cycle, src_file, coverage_type, fcn/line\n")
        else:
            cfile.write("# id:NNNNNN*_file, cycle, src_file, coverage_type, fcn/line\n")
        cfile.close()

    return


def init_tracking(cov_paths, cargs):
    cov_paths['dirs'] = {}

    cov_paths['top_dir'] = "%s/cov" % cargs.fot_fuzzing_dir
    cov_paths['web_dir'] = "%s/web" % cov_paths['top_dir']
    cov_paths['lcov_dir'] = "%s/lcov" % cov_paths['top_dir']
    cov_paths['diff_dir'] = "%s/diff" % cov_paths['top_dir']
    cov_paths['log_file'] = "%s/fot-cov.log" % cov_paths['top_dir']

    # global coverage results
    cov_paths['id_delta_cov'] = "%s/id-delta-cov" % cov_paths['top_dir']
    cov_paths['zero_cov'] = "%s/zero-cov" % cov_paths['top_dir']
    cov_paths['pos_cov'] = "%s/pos-cov" % cov_paths['top_dir']
    cov_paths['diff'] = ''
    cov_paths['id_file'] = ''
    cov_paths['id_min'] = -1  # used in --cover-corpus mode
    cov_paths['id_max'] = -1  # used in --cover-corpus mode

    # raw lcov files
    cov_paths['lcov_base'] = "%s/trace.lcov_base" % cov_paths['lcov_dir']
    cov_paths['lcov_info'] = "%s/trace.lcov_info" % cov_paths['lcov_dir']
    cov_paths['lcov_info_final'] = "%s/trace.lcov_info_final" % cov_paths['lcov_dir']

    if cargs.overwrite:
        mkdirs(cov_paths, cargs)
    else:
        if is_dir(cov_paths['top_dir']):
            if not cargs.func_search and not cargs.line_search:
                danger("[*] Existing coverage dir %s found, use --overwrite to "
                       "re-calculate coverage" % (cov_paths['top_dir']))
                return False
        else:
            mkdirs(cov_paths, cargs)

    write_status("%s/fot-cov-status" % cov_paths['top_dir'])

    if not cargs.disable_coverage_init and cargs.coverage_cmd:

        lcov_opts = ''
        if cargs.enable_branch_coverage:
            lcov_opts += ' --rc lcov_branch_coverage=1 '

        # reset code coverage counters - this is done only once as
        # fot-cov is spinning up even if FOT is running in parallel mode
        run_cmd(cargs.lcov_path
                + lcov_opts
                + " --no-checksum --zerocounters --directory "
                + cargs.code_dir, cov_paths['log_file'], cargs, LOG_ERRORS)

        run_cmd(cargs.lcov_path
                + lcov_opts
                + " --no-checksum --capture --initial"
                + " --directory " + cargs.code_dir
                + " --output-file "
                + cov_paths['lcov_base'],
                cov_paths['log_file'], cargs, LOG_ERRORS)

    return True


def import_fuzzing_dirs(cov_paths, cargs):
    if not cargs.fot_fuzzing_dir:
        print("[*] Must specify FOT fuzzing dir with --fot-fuzzing-dir or -d")
        return False

    if 'top_dir' not in cov_paths:
        if not init_tracking(cov_paths, cargs):
            return False

    def_dir = cargs.fot_fuzzing_dir

    if is_dir("%s/queue" % def_dir):
        if def_dir not in cov_paths['dirs']:
            add_dir(def_dir, cov_paths)
    else:
        for p in os.listdir(def_dir):
            fuzz_dir = "%s/%s" % (def_dir, p)
            if is_dir(fuzz_dir):
                if is_dir("%s/queue" % fuzz_dir):
                    # found an FOT fuzzing directory instance from
                    # parallel FOT execution
                    if fuzz_dir not in cov_paths['dirs']:
                        add_dir(fuzz_dir, cov_paths)

    return True


def import_test_cases(qdir):
    # return sorted(glob.glob(qdir + "/id:*"))
    return sorted(glob.glob(qdir + "/w*"))


def process_fot_test_cases(cargs):
    rv = True
    run_once = False
    tot_files = 0
    fuzz_dir = ''

    fot_files = []
    cov_paths = {}

    # main coverage tracking dictionary
    cov = {'zero': {}, 'pos': {}}

    while True:

        if not import_fuzzing_dirs(cov_paths, cargs):
            print("# No fuzzing dir imported!")
            rv = False
            break

        dir_ctr = 0
        last_dir = False

        do_coverage = True
        if cargs.cover_corpus:
            do_coverage = False

        for fuzz_dir in cov_paths['dirs']:
            print("# Checking the dir: %s" % fuzz_dir)
            do_break = False
            last_file = False
            num_files = 0
            new_files = []
            tmp_files = import_test_cases(fuzz_dir + '/queue')
            dir_ctr += 1
            f_ctr = 0

            if dir_ctr == len(cov_paths['dirs']):
                last_dir = True

            for f in tmp_files:
                if f not in fot_files:
                    fot_files.append(f)
                    new_files.append(f)

            if new_files:
                logr("\n*** Imported %d new test cases from: %s\n"
                     % (len(new_files), (fuzz_dir + '/queue')),
                     cov_paths['log_file'], cargs)

            for f in new_files:

                f_ctr += 1
                if f_ctr == len(new_files):
                    last_file = True

                if cargs.cover_corpus and last_dir and last_file:
                    # in --cover-corpus mode, only run lcov after all FOT
                    # test cases have been processed
                    do_coverage = True

                out_lines = []
                curr_cycle = get_cycle_num(num_files, cargs)

                logr("[+] FOT test case: %s (%d / %d), cycle: %d"
                     % (os.path.basename(f), num_files, len(fot_files),
                        curr_cycle), cov_paths['log_file'], cargs)

                cov_paths['diff'] = "%s/%s" % \
                                    (cov_paths['diff_dir'], os.path.basename(f))
                # id_range_update(f, cov_paths)

                # execute the command to generate code coverage stats
                # for the current FOT test case file
                if run_once:
                    run_cmd(cargs.coverage_cmd.replace('FOT_FILE', f),
                            cov_paths['log_file'], cargs, NO_OUTPUT)
                else:
                    out_lines = run_cmd(cargs.coverage_cmd.replace('FOT_FILE', f),
                                        cov_paths['log_file'], cargs, WANT_OUTPUT)[1]
                    run_once = True

                if cargs.fot_queue_id_limit \
                        and num_files >= cargs.fot_queue_id_limit - 1:
                    logr("[+] queue/ id limit of %d reached..."
                         % cargs.fot_queue_id_limit,
                         cov_paths['log_file'], cargs)
                    do_break = True
                    if cargs.cover_corpus and last_dir:
                        do_coverage = True

                if do_coverage and not cargs.coverage_at_exit:

                    # generate the code coverage stats for this test case
                    lcov_gen_coverage(cov_paths, cargs)

                    # diff to the previous code coverage, look for new
                    # lines/functions, and write out results
                    coverage_diff(curr_cycle, fuzz_dir, cov_paths, f,
                                  cov, cargs)

                    if cargs.cover_corpus:
                        # reset the range values
                        cov_paths['id_min'] = cov_paths['id_max'] = -1

                    if cargs.lcov_web_all:
                        gen_web_cov_report(fuzz_dir, cov_paths, cargs)

                    # log the output of the very first coverage command to
                    # assist in troubleshooting
                    if len(out_lines):
                        logr("\n\n++++++ BEGIN - first exec output for CMD: %s" %
                             (cargs.coverage_cmd.replace('FOT_FILE', f)),
                             cov_paths['log_file'], cargs)
                        for line in out_lines:
                            logr("    %s" % line, cov_paths['log_file'], cargs)
                        logr("++++++ END\n", cov_paths['log_file'], cargs)

                cov_paths['id_file'] = "%s" % os.path.basename(f)

                num_files += 1
                tot_files += 1

                if do_break:
                    break

        if cargs.live:
            if is_fot_fuzz_running(cargs):
                if not len(new_files):
                    logr("[-] No new FOT test cases, sleeping for %d seconds"
                         % cargs.sleep, cov_paths['log_file'], cargs)
                    time.sleep(cargs.sleep)
                    continue
            else:
                logr("[+] fot-fuzz appears to be stopped...",
                     cov_paths['log_file'], cargs)
                break
        # only go once through the loop unless we are in --live mode
        else:
            break

    if tot_files > 0:
        logr("[+] Processed %d / %d test cases.\n"
             % (tot_files, len(fot_files)),
             cov_paths['log_file'], cargs)

        if cargs.coverage_at_exit:
            # generate the code coverage stats for this test case
            lcov_gen_coverage(cov_paths, cargs)

            # diff to the previous code coverage, look for new
            # lines/functions, and write out results
            coverage_diff(curr_cycle, fuzz_dir, cov_paths,
                          cov_paths['id_file'], cov, cargs)

        # write out the final zero coverage and positive coverage reports
        write_zero_cov(cov['zero'], cov_paths, cargs)
        write_pos_cov(cov['pos'], cov_paths, cargs)

        if not cargs.disable_lcov_web:
            lcov_gen_coverage(cov_paths, cargs)
            gen_web_cov_report(fuzz_dir, cov_paths, cargs)

    else:
        if rv:
            logr("[*] Did not find any FOT test cases, exiting.\n",
                 cov_paths['log_file'], cargs)
        rv = False

    return rv


def main():
    exit_success = 0
    exit_failure = 1

    cargs = parse_cmdline()

    if cargs.version:
        info("fot-cov-" + __version__)
        return exit_success

    # if cargs.gcov_check or cargs.gcov_check_bin:
    #     if is_gcov_enabled(cargs):
    #         return exit_success
    #     else:
    #         return exit_failure
    #
    # if not check_requirements(cargs):
    #     return exit_failure
    #
    # if cargs.stop_fot:
    #     return not stop_fot(cargs)
    #
    # if not validate_cargs(cargs):
    #     return exit_failure
    #
    # if cargs.validate_args:
    #     return exit_success
    #
    # if cargs.func_search or cargs.line_search:
    #     return not search_cov(cargs)
    #
    # if cargs.background:
    #     run_in_background()
    #
    # if cargs.live:
    #     is_fot_running(cargs)

    return not process_fot_test_cases(cargs)


def parse_cmdline():
    p = argparse.ArgumentParser()

    p.add_argument("-e", "--coverage-cmd", type=str,
                   help="Set command to exec (including args, and assumes code coverage support)")
    p.add_argument("-d", "--fot-fuzzing-dir", type=str,
                   help="top level FOT fuzzing directory")
    p.add_argument("-c", "--code-dir", type=str,
                   help="Directory where the code lives (compiled with code coverage support)")
    p.add_argument("-f", "--follow", action='store_true',
                   help="Follow links when searching .da files", default=False)
    p.add_argument("-O", "--overwrite", action='store_true',
                   help="Overwrite existing coverage results", default=False)
    p.add_argument("--disable-cmd-redirection", action='store_true',
                   help="Disable redirection of command results to /dev/null",
                   default=False)
    p.add_argument("--disable-lcov-web", action='store_true',
                   help="Disable generation of all lcov web code coverage reports",
                   default=False)
    p.add_argument("--disable-coverage-init", action='store_true',
                   help="Disable initialization of code coverage counters at fot-cov startup",
                   default=False)
    p.add_argument("--coverage-include-lines", action='store_true',
                   help="Include lines in zero-coverage status files",
                   default=False)
    p.add_argument("--enable-branch-coverage", action='store_true',
                   help="Include branch coverage in code coverage reports (may be slow)",
                   default=False)
    p.add_argument("--live", action='store_true',
                   help="Process a live FOT directory, and fot-cov will exit when it appears fot-fuzz has been stopped",
                   default=False)
    p.add_argument("--cover-corpus", action='store_true',
                   help="Measure coverage after running all available tests instead of individually per queue file",
                   default=False)
    p.add_argument("--coverage-at-exit", action='store_true',
                   help="Only calculate coverage just before fot-cov exit.",
                   default=False)
    p.add_argument("--sleep", type=int,
                   help="In --live mode, # of seconds to sleep between checking for new queue files",
                   default=60)
    p.add_argument("--gcov-check", action='store_true',
                   help="Check to see if there is a binary in --coverage-cmd (or in --gcov-check-bin) has coverage "
                        "support",
                   default=False)
    p.add_argument("--gcov-check-bin", type=str,
                   help="Test a specific binary for code coverage support",
                   default=False)
    p.add_argument("--disable-gcov-check", type=str,
                   help="Disable check for code coverage support",
                   default=False)
    p.add_argument("--background", action='store_true',
                   help="Background mode - if also in --live mode, will exit when the alf-fuzz process is finished",
                   default=False)
    p.add_argument("--lcov-web-all", action='store_true',
                   help="Generate lcov web reports for all id:NNNNNN* files instead of just the last one",
                   default=False)
    p.add_argument("--disable-lcov-exclude-pattern", action='store_true',
                   help="Allow default /usr/include/* pattern to be included in lcov results",
                   default=False)
    p.add_argument("--lcov-exclude-pattern", type=str,
                   help="Set exclude pattern for lcov results",
                   default="/usr/include/\*")
    p.add_argument("--func-search", type=str,
                   help="Search for coverage of a specific function")
    p.add_argument("--line-search", type=str,
                   help="Search for coverage of a specific line number (requires --src-file)")
    p.add_argument("--src-file", type=str,
                   help="Restrict function or line search to a specific source file")
    p.add_argument("--fot-queue-id-limit", type=int,
                   help="Limit the number of id:NNNNNN* files processed in the FOT queue/ directory",
                   default=0)
    p.add_argument("--ignore-core-pattern", action='store_true',
                   help="Ignore the /proc/sys/kernel/core_pattern setting in --live mode",
                   default=False)
    p.add_argument("--lcov-path", type=str,
                   help="Path to lcov command", default="/usr/bin/lcov")
    p.add_argument("--genhtml-path", type=str,
                   help="Path to genhtml command", default="/usr/bin/genhtml")
    p.add_argument("--readelf-path", type=str,
                   help="Path to readelf command", default="/usr/bin/readelf")
    p.add_argument("--stop-fot", action='store_true',
                   help="Stop all running fot-fuzz instances associated with --fot-fuzzing-dir <dir>",
                   default=False)
    p.add_argument("--validate-args", action='store_true',
                   help="Validate args and exit", default=False)
    p.add_argument("-v", "--verbose", action='store_true',
                   help="Verbose mode", default=False)
    p.add_argument("-V", "--version", action='store_true',
                   help="Print version and exit", default=False)
    p.add_argument("-q", "--quiet", action='store_true',
                   help="Quiet mode", default=False)

    return p.parse_args()


if __name__ == "__main__":
    sys.exit(main())

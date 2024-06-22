from typing import List, Dict, Set, Tuple, Any
import unittest
import json
import logging
import shutil
import glob
import os

# test-global log configuration
logging.basicConfig(
    format="%(asctime)s,%(msecs)d %(levelname)-8s "
    "[%(filename)s:%(lineno)d] %(message)s",
    datefmt="%Y-%m-%d:%H:%M:%S",
)

# module-local log setup
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

DATA_DIR = "/data"
NEW_TA_DIR = os.path.join(DATA_DIR, "new")
ANALYSIS_DIR = os.path.join(DATA_DIR, "analysis")
IMPORTED_DIR = os.path.join(DATA_DIR, "imported")
TEST_DIR = "/test"

TAS = [
    "000cafee-2450-11e4-abe2-0002a5d5c51b.elf",
    "001cafee-2450-11e4-abe2-0002a5d5c51b.elf",
    "002cafee-2450-11e4-abe2-0002a5d5c51b.elf",
    "003cafee-2450-11e4-abe2-0002a5d5c51b.elf",
    "004cafee-2450-11e4-abe2-0002a5d5c51b.elf",
]


class TipiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ghidraproj_dir = os.path.join(DATA_DIR, "GhidraProject.rep")
        ghidra_file = os.path.join(DATA_DIR, "GhidraProject.gpr")

        if os.path.isdir(ANALYSIS_DIR):
            shutil.rmtree(ANALYSIS_DIR)
        if os.path.isdir(IMPORTED_DIR):
            shutil.rmtree(IMPORTED_DIR)
        if os.path.isdir(ghidraproj_dir):
            shutil.rmtree(ghidraproj_dir)
        if os.path.isfile(ghidra_file):
            os.remove(ghidra_file)

        os.mkdir(ANALYSIS_DIR)
        os.mkdir(IMPORTED_DIR)

        test_tas = [
            ta
            for ta in glob.glob(f"{TEST_DIR}/*-tipi/*.elf")
            if not ta.endswith(".stripped.elf")
        ]
        for ta in test_tas:
            shutil.copy(ta, os.path.join(NEW_TA_DIR, os.path.basename(ta)))

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def _run_and_report(self, ta: str) -> Dict[str, Any]:
        os.system(f"/tipi-entrypoint.sh {ta} optee")
        report_path = os.path.join(ANALYSIS_DIR, ta, "report.json")
        assert os.path.isfile(report_path)
        with open(report_path) as f:
            report = json.load(f)
        return report

    def test_value_intra_proc_no_check(self):
        ta = TAS[0]
        report = self._run_and_report(ta)
        assert report["is_vuln"] == False

    def test_memref_intra_proc_no_check(self):
        ta = TAS[1]
        report = self._run_and_report(ta)
        assert report["is_vuln"] == True

    def test_memref_intra_proc_check(self):
        ta = TAS[2]
        report = self._run_and_report(ta)
        assert report["is_vuln"] == False

    def test_memref_intra_proc_wrong_check(self):
        ta = TAS[3]
        report = self._run_and_report(ta)
        assert report["is_vuln"] == True

    def test_memref_inter_proc_no_check(self):
        ta = TAS[4]
        report = self._run_and_report(ta)
        assert report["is_vuln"] == True


if __name__ == "__main__":
    unittest.main()

"""
tests/test_paper_numbers_consistency.py: Unit test ensuring paper.md
strictly follows unified rounding (round half up, 1 decimal) and consistent Wilson CIs.
"""

import unittest
from pathlib import Path
from scripts.check_numbers import (
    check_paper_numbers,
    check_exposure_bounds,
    check_cross_table_consistency,
)


class TestPaperNumbersConsistency(unittest.TestCase):

    def setUp(self):
        self.root = Path(__file__).resolve().parent.parent
        self.paper_path = self.root / "paper.md"

    def test_all_percentages_and_wilson_cis_consistent(self):
        """Verifies that all x% (n/N) and Wilson CIs in paper.md match exact calculations."""
        self.assertTrue(self.paper_path.exists(), f"paper.md missing at {self.paper_path}")
        total_checked, mismatches = check_paper_numbers(self.paper_path)
        self.assertGreater(total_checked, 0, "No expressions were checked in paper.md")
        
        if mismatches:
            msg_lines = [f"Found {len(mismatches)} numerical mismatches in paper.md:"]
            for m in mismatches:
                if m["type"] == "percentage":
                    msg_lines.append(f"  Line {m['line']}: {m['raw']} -> Observed {m['observed']}%, Expected {m['expected']}% ({m['n']}/{m['N']})")
                else:
                    msg_lines.append(f"  Line {m['line']}: {m['raw']} -> Observed [{m['observed'][0]}%, {m['observed'][1]}%], Expected [{m['expected'][0]}%, {m['expected'][1]}%] for ({m['k']}/{m['n']})")
            self.fail("\n".join(msg_lines))

    def test_exposure_windows_within_bounds(self):
        """Verifies that every reported mean exposure window lies in [0, max possible for chain lengths = 2.0]."""
        self.assertTrue(self.paper_path.exists(), f"paper.md missing at {self.paper_path}")
        total_checked, out_of_bounds = check_exposure_bounds(self.paper_path, max_exposure=2.0)
        self.assertGreater(total_checked, 0, "No exposure windows were checked in paper.md")
        if out_of_bounds:
            msg_lines = [f"Found {len(out_of_bounds)} exposure windows out of bounds [0, 2.0]:"]
            for item in out_of_bounds:
                msg_lines.append(f"  Line {item['line']}: {item['raw']} (value {item['value']} > max {item['max_allowed']})")
            self.fail("\n".join(msg_lines))

    def test_cross_table_configuration_consistency(self):
        """Verifies that identical defense configurations have identical values across Tables 6, 7, 8, A.1, A.2, and prose."""
        self.assertTrue(self.paper_path.exists(), f"paper.md missing at {self.paper_path}")
        total_checked, mismatches = check_cross_table_consistency(self.paper_path)
        self.assertGreater(total_checked, 0, "No cross-table configurations were checked in paper.md")
        if mismatches:
            msg_lines = [f"Found {len(mismatches)} cross-table inconsistencies:"]
            for m in mismatches:
                msg_lines.append(f"  {m}")
            self.fail("\n".join(msg_lines))


if __name__ == "__main__":
    unittest.main()

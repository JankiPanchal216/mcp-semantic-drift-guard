"""
tests/test_paper_numbers_consistency.py: Unit test ensuring paper.md
strictly follows unified rounding (round half up, 1 decimal) and consistent Wilson CIs.
"""

import unittest
from pathlib import Path
from scripts.check_numbers import check_paper_numbers


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


if __name__ == "__main__":
    unittest.main()

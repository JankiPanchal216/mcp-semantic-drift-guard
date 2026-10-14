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
    def test_table_order_and_references(self):
        """Verifies that all tables appear in sequential order and all referenced tables exist."""
        from scripts.check_numbers import check_table_order_and_references
        self.assertTrue(self.paper_path.exists(), f"paper.md missing at {self.paper_path}")
        total_checked, errors = check_table_order_and_references(self.paper_path)
        self.assertGreater(total_checked, 0, "No table order/references checked")
        if errors:
            msg = "\n".join([f"  {e['type']} error: {e['error']}" for e in errors])
            self.fail(f"Found {len(errors)} table ordering/reference errors in paper.md:\n{msg}")

    def test_paper_tables_match_generated_tables(self):
        """For every table in results/tables/tables_markdown.md that also appears in paper.md,
        the whitespace-normalised markdown block must be identical.
        Fails with the table name and first differing row.
        """
        import re
        tables_md_path = self.root / "results" / "tables" / "tables_markdown.md"
        self.assertTrue(tables_md_path.exists(), f"tables_markdown.md missing at {tables_md_path}")
        self.assertTrue(self.paper_path.exists(), f"paper.md missing at {self.paper_path}")

        def parse_tables(text):
            tables = {}
            lines = text.splitlines()
            i = 0
            while i < len(lines):
                line = lines[i].strip()
                m = re.search(r'(?:^##+\s*|^\*\s*|\b)(Table\s+(?:[0-9]+[a-z]?|A\.[0-9]+))\b', line)
                if m and (line.startswith('#') or line.startswith('*Table')):
                    t_id = m.group(1).replace('  ', ' ')
                    table_lines = []
                    j = i + 1
                    while j < len(lines) and not lines[j].strip().startswith('|'):
                        if lines[j].strip().startswith('#'):
                            break
                        j += 1
                    if j < len(lines) and lines[j].strip().startswith('|'):
                        while j < len(lines) and lines[j].strip().startswith('|'):
                            table_lines.append(lines[j].strip())
                            j += 1
                    else:
                        k = i - 1
                        while k >= 0 and not lines[k].strip().startswith('|'):
                            if lines[k].strip().startswith('#'):
                                break
                            k -= 1
                        if k >= 0 and lines[k].strip().startswith('|'):
                            while k >= 0 and lines[k].strip().startswith('|'):
                                table_lines.insert(0, lines[k].strip())
                                k -= 1
                    if table_lines:
                        tables[t_id] = table_lines
                i += 1
            return tables

        def norm_row(r):
            return ' | '.join(c.strip() for c in r.strip().strip('|').split('|'))

        p_tables = parse_tables(self.paper_path.read_text(encoding='utf-8'))
        g_tables = parse_tables(tables_md_path.read_text(encoding='utf-8'))

        common_ids = sorted(list(set(g_tables.keys()) & set(p_tables.keys())))
        self.assertGreater(len(common_ids), 0, "No common tables found between tables_markdown.md and paper.md")

        for t_id in common_ids:
            g_rows = g_tables[t_id]
            p_rows = p_tables[t_id]
            if len(g_rows) != len(p_rows):
                self.fail(f"Table '{t_id}' row count mismatch: generated table has {len(g_rows)} rows, but paper.md has {len(p_rows)} rows.\nFirst differing row: {g_rows[min(len(g_rows), len(p_rows))-1]}")
            for r_idx, (gr, pr) in enumerate(zip(g_rows, p_rows)):
                norm_gr = norm_row(gr)
                norm_pr = norm_row(pr)
                if norm_gr != norm_pr:
                    self.fail(
                        f"Table '{t_id}' differing row at index {r_idx}:\n"
                        f"Generated: {norm_gr}\n"
                        f"Paper:     {norm_pr}"
                    )

    def test_preregistration_h1_matches_paper_h1(self):
        """Asserts that the H1 sentence in PREREGISTRATION.md and paper.md match character-for-character."""
        prereg_path = self.root / "paper" / "PREREGISTRATION.md"
        self.assertTrue(prereg_path.exists(), f"PREREGISTRATION.md missing at {prereg_path}")
        
        prereg_text = prereg_path.read_text(encoding="utf-8")
        paper_text = self.paper_path.read_text(encoding="utf-8")
        
        def extract_h1(text):
            for line in text.splitlines():
                if "H_1" in line and ":**" in line and line.strip().startswith("-"):
                    return line.split(":**", 1)[1].strip()
            return None
        
        h1_prereg = extract_h1(prereg_text)
        self.assertIsNotNone(h1_prereg, "Failed to find H1 in PREREGISTRATION.md")
        
        h1_paper = extract_h1(paper_text)
        self.assertIsNotNone(h1_paper, "Failed to find Hypothesis H1 in paper.md")
        
        self.assertEqual(
            h1_prereg,
            h1_paper,
            f"H1 mismatch between PREREGISTRATION.md and paper.md:\nPREREG: {h1_prereg}\nPAPER:  {h1_paper}"
        )


if __name__ == "__main__":
    unittest.main()

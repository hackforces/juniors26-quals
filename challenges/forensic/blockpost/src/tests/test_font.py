import importlib.util
import unittest

from mc_blockpost.font import FONT, GLYPH_H, GLYPH_TO_CHAR, GLYPH_W

from .util import AUTHOR_SOLVER


class FontTest(unittest.TestCase):
    def test_alphabet(self):
        expected = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}")
        self.assertEqual(set(FONT), expected)

    def test_glyphs_are_5x5(self):
        for ch, rows in FONT.items():
            with self.subTest(ch=ch):
                self.assertEqual(len(rows), GLYPH_H)
                for r in rows:
                    self.assertEqual(len(r), GLYPH_W)
                    self.assertLessEqual(set(r), {"#", "."})
                self.assertIn("#", "".join(rows))

    def test_no_collisions(self):
        self.assertEqual(len(GLYPH_TO_CHAR), len(FONT))
        for ch, rows in FONT.items():
            self.assertEqual(GLYPH_TO_CHAR[tuple(rows)], ch)

    def test_author_solver_font_matches(self):
        spec = importlib.util.spec_from_file_location("author_solve", AUTHOR_SOLVER)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.assertEqual(mod.FONT, {k: "".join(v) for k, v in FONT.items()})


if __name__ == "__main__":
    unittest.main()

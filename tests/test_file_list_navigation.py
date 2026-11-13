"""Synthetic file-list navigation checks using real Tk widgets."""
import tkinter as tk
from tkinter import ttk
from types import SimpleNamespace
import unittest

from log_hunter.ui.file_list import FileListView


class FileListNavigationTests(unittest.TestCase):
    def setUp(self):
        try:
            self.root = tk.Tk()
        except tk.TclError as error:
            self.skipTest(f"Tk display unavailable: {error}")
        self.addCleanup(self.root.destroy)
        book = ttk.Notebook(self.root)
        book.pack(fill='both', expand=True)
        noop = lambda *args: None
        self.view = FileListView(book, noop, noop, noop, noop, noop, noop, noop)

    def test_reveal_clears_filter_and_selects_correct_page(self):
        rows = [{'name': f'{i:04}.txt', 'parts': ('Documents', f'{i:04}.txt')}
                for i in range(2005)]
        self.view.show(rows, 'synthetic')
        self.view.query.set('0000')
        self.assertTrue(self.view.select_path(('documents', '2004.TXT')))
        self.assertEqual(self.view.model.page, 1)
        self.assertEqual(self.view.selected_row()['name'], '2004.txt')
        self.assertFalse(self.view.select_path(('missing.txt',)))

    def test_activation_uses_clicked_row_and_ignores_empty_area(self):
        self.view.show([{'name': 'sample.txt', 'parts': ('sample.txt',)}], 'synthetic')
        self.root.update()
        box = self.view.table.bbox('r0')
        calls = []
        self.view._activate(SimpleNamespace(y=box[1] + 2), calls.append)
        self.assertEqual(calls[0]['name'], 'sample.txt')
        self.view._activate(SimpleNamespace(y=10000), calls.append)
        self.assertEqual(len(calls), 1)

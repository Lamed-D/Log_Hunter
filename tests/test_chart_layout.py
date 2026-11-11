import tkinter as tk
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from log_hunter.ui.charts import Dashboard, chart_counts, draw_dashboard, top_items


class ChartLayoutTests(unittest.TestCase):
    def test_layout_matrix(self):
        root = tk.Tk()
        try:
            for scaling in (1.333333, 2.0):
                root.tk.call('tk', 'scaling', scaling)
                for width, height in ((900, 600), (1400, 850), (1920, 1080)):
                    for count in (0, 1, 26, 100, -1, -2):
                        with self.subTest(scaling=scaling, size=(width, height), count=count):
                            root.geometry(f'{width}x{height}')
                            canvas = tk.Canvas(root)
                            canvas.pack(fill='both', expand=True)
                            root.update()
                            events = [SimpleNamespace(artifact='설치·실행된 프로그램 목록'*4+str(i),
                                      action='긴 한국어 활동 이름'*5+str(i), status='ok',
                                      timestamp=None if i % 2 else '2024-01-01T00:00:00+00:00')
                                      for i in range(max(1, count) if count < 0 else count)]
                            if count == -2:
                                for event in events:
                                    event.timestamp = None
                            def draw():
                                if count == -1:
                                    with patch('log_hunter.ui.charts.chart_counts', return_value=(
                                            {'evtx': 1000000, 'lnk': 1}, {'large': 1000000, 'small': 1},
                                            {'ok': 1000001}, {'00': 1000001}, [[1000001] + [0]*23] + [[0]*24 for _ in range(6)])):
                                        draw_dashboard(canvas, events)
                                else:
                                    draw_dashboard(canvas, events)
                            draw()
                            first = len(canvas.find_all())
                            draw()
                            self.assertEqual(first, len(canvas.find_all()))
                            region = tuple(map(float, canvas.cget('scrollregion').split()))
                            boxes = []
                            for item in canvas.find_all():
                                box = canvas.bbox(item)
                                self.assertGreaterEqual(box[0], region[0])
                                self.assertGreaterEqual(box[1], region[1])
                                self.assertLessEqual(box[2], region[2])
                                self.assertLessEqual(box[3], region[3])
                                if canvas.type(item) == 'text':
                                    for other in boxes:
                                        self.assertFalse(box[0] < other[2] and other[0] < box[2]
                                                         and box[1] < other[3] and other[1] < box[3], (box, other))
                                    boxes.append(box)
                                    for shape in canvas.find_all():
                                        if canvas.type(shape) == 'rectangle':
                                            other = canvas.bbox(shape)
                                            self.assertFalse(box[0] < other[2] and other[0] < box[2]
                                                             and box[1] < other[3] and other[1] < box[3], (box, other))
                            bars = canvas.find_withtag('bar')
                            for item in bars:
                                tags = canvas.gettags(item)
                                value = int(next(t[6:] for t in tags if t.startswith('value:')))
                                maximum = int(next(t[8:] for t in tags if t.startswith('maximum:')))
                                x1, _, x2, _ = canvas.coords(item)
                                series = next(t for t in tags if t.startswith('series:'))
                                full = max(canvas.coords(b)[2] - canvas.coords(b)[0]
                                           for b in canvas.find_withtag(series))
                                self.assertAlmostEqual((x2-x1)/full, value/maximum)
                            canvas.destroy()
        finally:
            root.destroy()

    def test_totals_large_values_and_timezones(self):
        data = {str(i): 1 for i in range(26)}
        data['large'] = 1000000
        items = top_items(data)
        self.assertEqual(sum(v for _, v in items), 1000026)
        self.assertEqual(items[-1], (None, 15))
        events = [SimpleNamespace(artifact='evtx', action='event', status='ok', timestamp=t)
                  for t in (None, 'invalid', '2024-01-01T00:00:00', '2024-01-01T01:00:00+01:00')]
        self.assertEqual(chart_counts(events)[3], {'00': 1})

    def test_resize_debounce(self):
        root = tk.Tk()
        try:
            canvas = tk.Canvas(root)
            canvas.pack(fill='both', expand=True)
            root.update()
            dashboard = Dashboard(canvas)
            dashboard.set_events([SimpleNamespace(artifact='evtx', action='event', status='ok', timestamp=None)])
            old = dashboard.pending
            dashboard.schedule()
            self.assertNotEqual(old, dashboard.pending)
            root.after(150, root.quit)
            root.mainloop()
            before = canvas.cget('scrollregion')
            root.geometry('1400x850')
            root.after(200, root.quit)
            root.mainloop()
            self.assertNotEqual(before, canvas.cget('scrollregion'))
            self.assertIsNone(dashboard.pending)
        finally:
            root.destroy()

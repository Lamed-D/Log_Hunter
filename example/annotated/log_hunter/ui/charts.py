# ▶ 원본: log_hunter/ui/charts.py
# ▶ 분석 기록의 분포를 표시할 Tkinter 그림 요소를 만듭니다.
# ▶ 실행 코드는 원본과 동일하며 이 접두어의 줄은 학습 해설입니다.
"""Measured, scrollable statistics charts with bounded legends."""
from collections import Counter
from datetime import datetime, timezone
from tkinter import font

from log_hunter.core.labels import CHART_LABELS, action_label, artifact_label, status_label
from .style import ARTIFACT_COLORS, BAR_COLORS


def top_items(data, limit=12):
    """Keep totals when limiting a chart, without requiring Tk."""
    items = sorted(data.items(), key=lambda item: (-item[1], str(item[0])))
    if len(items) <= limit:
        return items
    return items[:limit] + [(None, sum(value for _, value in items[limit:]))]


def _shorten(value, measure, width):
    text = str(value).replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
    if measure(text) <= width:
        return text
    low, high = 0, len(text)
    while low < high:
        mid = (low + high + 1) // 2
        if measure(text[:mid] + '…') <= width:
            low = mid
        else:
            high = mid - 1
    return text[:low] + '…'


def chart_counts(events):
    """Aggregate once; unknown or timezone-less times are not guessed as UTC."""
    arts, actions, statuses, hours = Counter(), Counter(), Counter(), Counter()
    grid = [[0] * 24 for _ in range(7)]
    for event in events:
        arts[event.artifact] += 1
        actions[event.action] += 1
        statuses[event.status] += 1
        try:
            dt = datetime.fromisoformat(event.timestamp)
            if dt.tzinfo is None:
                continue
            dt = dt.astimezone(timezone.utc)
        except (ValueError, TypeError):
            continue
        hours[f'{dt.hour:02d}'] += 1
        grid[dt.weekday()][dt.hour] += 1
    return arts, actions, statuses, hours, grid


def draw_dashboard(canvas, events):
    """Draw within a logical scroll region; return full labels for tooltips."""
    canvas.delete('all')
    normal = font.Font(root=canvas, family='Segoe UI', size=9)
    bold = font.Font(root=canvas, family='Segoe UI', size=10, weight='bold')
    line = max(normal.metrics('linespace'), bold.metrics('linespace')) + 12
    pad = 16
    width = max(canvas.winfo_width(), normal.measure('00') * 24 + 2 * pad + 50)
    y = pad
    tooltip = {}

    def text(x, yy, value, **kwargs):
        return canvas.create_text(x, yy, text=value, anchor='nw', font=normal, **kwargs)

    def bars(data, title, labeler=str):
        nonlocal y
        text(pad, y, title)
        y += line
        items = top_items(data)
        if not items:
            text(pad, y, CHART_LABELS['empty'])
            y += line
            return
        values_width = max(normal.measure(f'{value:,}') for _, value in items) + 12
        label_width = min(width * .35, max(normal.measure(str(labeler(key))) if key is not None
                                              else normal.measure(CHART_LABELS['other']) for key, _ in items))
        bx = pad + label_width + 16
        available = max(1, width - pad - bx - values_width - 12)
        maximum = max(value for _, value in items) or 1
        for i, (key, value) in enumerate(items):
            full = CHART_LABELS['other'] if key is None else str(labeler(key))
            item = text(pad, y, _shorten(full, normal.measure, label_width))
            tooltip[item] = full
            color = ARTIFACT_COLORS.get(key, BAR_COLORS[i % len(BAR_COLORS)])
            canvas.create_rectangle(bx, y + 3, bx + available * value / maximum,
                                    y + normal.metrics('linespace') - 1, fill=color, outline='',
                                    tags=('bar', f'series:{title}', f'value:{value}', f'maximum:{maximum}'))
            text(width - pad - values_width, y, f'{value:,}')
            y += line
        y += line // 2

    if not events:
        text(pad, y, CHART_LABELS['empty'])
        y += line
    else:
        arts, actions, statuses, hours, grid = chart_counts(events)
        bars(arts, CHART_LABELS['artifacts'], artifact_label)
        bars(actions, CHART_LABELS['actions'], action_label)
        bars(statuses, CHART_LABELS['statuses'], status_label)
        # All 24 hours are retained; no "other" bucket for a time axis.
        text(pad, y, CHART_LABELS['hours'])
        y += line
        cell_width = (width - 2 * pad - 32) / 24
        stride = max(1, int((normal.measure('00') + 8) / cell_width) + 1)
        for hour in range(0, 24, stride):
            text(pad + 32 + hour * cell_width, y, f'{hour:02d}')
        y += line
        maximum = max(hours.values(), default=0) or 1
        chart_height = line * 4
        for hour in range(24):
            bx = pad + 32 + hour * cell_width
            canvas.create_rectangle(bx, y + chart_height * (1 - hours.get(f'{hour:02d}', 0) / maximum),
                                    bx + cell_width - 3, y + chart_height, fill=BAR_COLORS[1], outline='')
        y += chart_height + line
        text(pad, y, CHART_LABELS['heatmap'])
        y += line
        for hour in range(0, 24, stride):
            text(pad + 32 + hour * cell_width, y, f'{hour:02d}')
        y += line
        maximum = max(map(max, grid)) or 1
        for day, label in enumerate(CHART_LABELS['weekdays']):
            text(pad, y, label)
            for hour in range(24):
                intensity = grid[day][hour] / maximum
                color = f'#{int(255-intensity*200):02x}{int(255-intensity*255):02x}{int(255-intensity*200):02x}'
                bx = pad + 32 + hour * cell_width
                item = canvas.create_rectangle(bx, y, bx + cell_width - 2, y + line - 5,
                                               fill=color, outline='#ddd')
                tooltip[item] = f'{label} {hour:02d}: {grid[day][hour]:,}'
            y += line
    canvas.configure(scrollregion=(0, 0, width, max(y + pad, canvas.winfo_height())))
    return tooltip


class Dashboard:
    """Debounce resize draws; keep aggregation out of Configure event bursts."""
    def __init__(self, canvas):
        self.canvas = canvas
        self.events = []
        self.pending = None
        self.tooltips = {}
        self.tip = None
        canvas.bind('<Configure>', self.schedule, add='+')
        canvas.bind('<Motion>', self.hover, add='+')
        canvas.bind('<Leave>', self.hide_tip, add='+')
        canvas.bind('<Destroy>', self.destroy, add='+')

    def set_events(self, events):
        self.events = events
        self.schedule()

    def schedule(self, event=None):
        if self.pending is not None:
            self.canvas.after_cancel(self.pending)
        self.pending = self.canvas.after(80, self.redraw)

    def redraw(self):
        self.pending = None
        self.hide_tip()
        self.tooltips = draw_dashboard(self.canvas, self.events)

    def hide_tip(self, event=None):
        if self.tip is not None:
            self.tip.destroy()
            self.tip = None

    def hover(self, event):
        import tkinter as tk
        self.hide_tip()
        x, y = self.canvas.canvasx(event.x), self.canvas.canvasy(event.y)
        for item in self.canvas.find_overlapping(x, y, x, y):
            if item in self.tooltips:
                self.tip = tk.Toplevel(self.canvas)
                self.tip.overrideredirect(True)
                self.tip.geometry(f'+{event.x_root + 12}+{event.y_root + 12}')
                tk.Label(self.tip, text=self.tooltips[item], wraplength=500,
                         background='#ffffe0', padx=5, pady=3).pack()
                break

    def destroy(self, event):
        if event.widget == self.canvas:
            if self.pending is not None:
                self.canvas.after_cancel(self.pending)
                self.pending = None
            self.hide_tip()

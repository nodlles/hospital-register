from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class UiLogRenderingTests(unittest.TestCase):
    def test_monitor_log_panel_has_task_summary_above_logs(self) -> None:
        html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")

        self.assertIn('id="taskSummary"', html)
        self.assertLess(html.index('id="taskSummary"'), html.index('id="logs"'))

    def test_render_logs_shows_newest_log_first(self) -> None:
        js = (ROOT / "web" / "app.js").read_text(encoding="utf-8")

        self.assertIn("function renderTaskSummary", js)
        self.assertIn("task.logs || []).slice().reverse()", js)

    def test_calendar_rendering_selects_backend_default_date(self) -> None:
        js = (ROOT / "web" / "app.js").read_text(encoding="utf-8")

        self.assertIn("item.defaultSelected", js)
        self.assertIn('"dateSelect").value = defaultItem.visitDate', js)

    def test_date_picker_has_compact_detail_area(self) -> None:
        html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
        css = (ROOT / "web" / "styles.css").read_text(encoding="utf-8")
        js = (ROOT / "web" / "app.js").read_text(encoding="utf-8")

        self.assertIn('class="grid-2 date-period-grid"', html)
        self.assertIn('id="dateDetail"', html)
        self.assertIn(".date-period-grid", css)
        self.assertIn(".date-detail", css)
        self.assertNotIn('class="date-field"', html)
        self.assertIn("renderDateDetail", js)

    def test_calendar_options_keep_auxiliary_release_text_outside_select(self) -> None:
        js = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
        css = (ROOT / "web" / "styles.css").read_text(encoding="utf-8")

        self.assertIn("calendarOptionLabel", js)
        self.assertIn("renderDateDetail", js)
        self.assertIn("date-detail pending", js)
        self.assertIn("预计放号", js)
        self.assertIn(".date-detail.pending", css)
        self.assertNotIn("预计${shortDateTime(item.estimatedReleaseAt)}放号", js)

    def test_notify_panel_uses_compact_grouped_layout(self) -> None:
        html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
        css = (ROOT / "web" / "styles.css").read_text(encoding="utf-8")

        self.assertIn('class="notify-toolbar"', html)
        self.assertIn('class="notify-switch"', html)
        self.assertIn('id="notifyToggleTitle"', html)
        self.assertIn('id="notifyToggleDetail"', html)
        self.assertIn('class="mini-state warning"', html)
        self.assertIn("notify-persist-1", html)
        self.assertIn('class="grid-2 notify-primary-grid"', html)
        self.assertIn('class="notify-fields"', html)
        self.assertIn('class="actions notify-actions"', html)
        self.assertIn(".notify-toolbar", css)
        self.assertIn(".notify-switch", css)
        self.assertIn(".notify-toggle input:checked + .notify-switch", css)
        self.assertIn(".mini-state.warning", css)
        self.assertIn(".notify-primary-grid", css)
        self.assertIn(".notify-fields", css)
        self.assertIn(".notify-telegram", css)
        self.assertIn("minmax(240px, 320px)", css)

    def test_notify_status_updates_enable_state_copy(self) -> None:
        js = (ROOT / "web" / "app.js").read_text(encoding="utf-8")

        self.assertIn("function renderNotifyStatus", js)
        self.assertIn("function notifyChannelLabel", js)
        self.assertIn('"Telegram"', js)
        self.assertIn('"Server 酱"', js)
        self.assertIn('"已配置，未启用"', js)
        self.assertIn("`当前渠道：${channelLabel}`", js)
        self.assertIn("`${channelLabel} · ${status}`", js)
        self.assertIn('notifyEnabled").addEventListener("change"', js)
        self.assertIn("await saveNotify({ statusOnly: true })", js)
        self.assertIn("通知已启用并保存", js)

    def test_main_layout_places_notify_under_logs_in_right_column(self) -> None:
        html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
        css = (ROOT / "web" / "styles.css").read_text(encoding="utf-8")

        self.assertIn('class="layout-column left-column"', html)
        self.assertIn('class="layout-column right-column"', html)
        self.assertIn('class="panel source-panel"', html)
        self.assertLess(html.index('class="layout-column right-column"'), html.index('class="panel notify-panel"'))
        self.assertLess(html.index('class="panel source-panel"'), html.index('class="panel log-panel"'))
        self.assertLess(html.index('class="panel log-panel"'), html.index('class="panel notify-panel"'))
        self.assertIn('"left right"', css)
        self.assertIn("grid-area: left", css)
        self.assertIn("grid-area: right", css)

    def test_control_panel_uses_left_column_spare_height(self) -> None:
        html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
        css = (ROOT / "web" / "styles.css").read_text(encoding="utf-8")

        self.assertIn('class="dept-field"', html)
        self.assertIn("align-items: stretch", css)
        self.assertIn("grid-template-rows: 1fr", css)
        self.assertIn("grid-template-rows: auto auto minmax(320px, 1fr)", css)
        self.assertIn(".dept-field select[size]", css)
        self.assertIn("height: 100%", css)


if __name__ == "__main__":
    unittest.main()

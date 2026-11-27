import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import { createApiClient, type ApiClient } from "../../api";
import type { CaptureSettingsView } from "../../lib/settings/types";
import {
  CaptureSettingsBody,
  CaptureSettingsCard,
  CaptureSettingsFields,
  captureDraftChanged,
  captureDraftFromView,
  captureUpdateFromDraft,
  emptyCaptureForm,
  formatWait,
  loadCaptureForm,
  resetCaptureForm,
  retryDelaysMS,
  saveCaptureForm,
  worstCaseWaitMS,
} from "./capture-settings-form";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function captureView(overrides: Partial<CaptureSettingsView> = {}): CaptureSettingsView {
  return { source: "file", settings: { commit_retries: 3 }, file: { commit_retries: 3 }, write_path: "unified", ...overrides };
}

const noop = () => undefined;

describe("audit capture settings form", () => {
  it("builds the request from the draft", () => {
    const view = captureView();
    const draft = captureDraftFromView(view);
    expect(draft).toEqual({ commit_retries: "3" });
    expect(captureDraftChanged(draft, view)).toBe(false);
    expect(captureUpdateFromDraft({ commit_retries: " 0 " })).toEqual({ commit_retries: 0 });
    expect(captureDraftChanged({ commit_retries: "0" }, view)).toBe(true);
    // Not a whole number: sent as -1 so the server names the field.
    for (const text of ["", "1.5", "two", "-1"]) {
      expect(captureUpdateFromDraft({ commit_retries: text }).commit_retries).toBe(-1);
    }
  });

  it("says how long each value can keep the handler waiting", () => {
    expect(retryDelaysMS(0)).toEqual([]);
    expect(retryDelaysMS(5)).toEqual([100, 200, 400, 800, 1000]);
    expect([0, 1, 2, 3, 4, 5].map(worstCaseWaitMS)).toEqual([0, 100, 300, 700, 1500, 2500]);
    expect(formatWait(0)).toBe("不等待");
    expect(formatWait(700)).toBe("0.7 秒");
    expect(formatWait(2500)).toBe("2.5 秒");
  });

  it("shows the value in use, where it comes from and the file's value", () => {
    const view = captureView();
    const html = renderToStaticMarkup(<CaptureSettingsFields view={view} draft={captureDraftFromView(view)} busy={false} onChange={noop} />);
    expect(html).toContain("来自配置文件");
    expect(html).toMatch(/id="capture-commit_retries"[^>]*value="3"/);
    expect(html).toContain("配置文件的值是 3");
    expect(html).toContain("audit.commit_retries");
    expect(html).toContain("只在 <span class=\"font-mono\">audit.write_path</span> 为 <span class=\"font-mono\">unified</span> 时生效");
    expect(html).toContain("0 表示只尝试一次，不重试");
    expect(html).toContain("第 1 次重试之前等 100 毫秒，之后每次翻倍，最长 1 秒");
    expect(html).toContain("填 3 时最多尝试 4 次，处理这条请求最多多等 0.7 秒，另加各次尝试本身的时间");
    expect(html).toContain("重试 5 次");
    expect(html).toContain("2.5 秒");
    expect(html).not.toContain("当前写入路径是");

    const zero = renderToStaticMarkup(<CaptureSettingsFields view={view} draft={{ commit_retries: "0" }} busy={false} onChange={noop} />);
    expect(zero).toContain("填 0 时只尝试一次，不重试，也不多等");
    expect(zero).not.toContain("最多尝试");
    const invalid = renderToStaticMarkup(<CaptureSettingsFields view={view} draft={{ commit_retries: "9" }} busy={false} onChange={noop} />);
    expect(invalid).toContain("要填 0 到 5 之间的整数");

    const saved = renderToStaticMarkup(
      <CaptureSettingsFields view={captureView({ source: "saved", updated_ns: "1800000000000000000", settings: { commit_retries: 0 } })} draft={{ commit_retries: "0" }} busy={false} onChange={noop} />,
    );
    expect(saved).toContain("覆盖配置文件");
    expect(saved).toContain("保存于");
    // On the legacy path the value is not used, and the page says so.
    const legacy = renderToStaticMarkup(<CaptureSettingsFields view={captureView({ write_path: "legacy" })} draft={{ commit_retries: "3" }} busy={false} onChange={noop} />);
    expect(legacy).toContain("当前写入路径是 <span class=\"font-mono\">legacy</span>");
    expect(renderToStaticMarkup(<CaptureSettingsCard client={{} as ApiClient} />)).toContain(">审计写入<");
  });

  it("talks to the settings route", async () => {
    const view = captureView();
    const fetcher = vi.fn<typeof fetch>(async () => jsonResponse(view));
    const client = createApiClient(vi.fn(), fetcher);
    await expect(client.getCaptureSettings()).resolves.toEqual(view);
    expect(String(fetcher.mock.calls[0][0])).toBe("/api/v1/settings/audit-capture");
    await client.saveCaptureSettings({ commit_retries: 0 });
    expect(fetcher.mock.calls[1][1]?.method).toBe("PUT");
    expect(JSON.parse(String(fetcher.mock.calls[1][1]?.body))).toEqual({ commit_retries: 0 });
    await expect(client.resetCaptureSettings()).resolves.toEqual(view);
    expect(fetcher.mock.calls[2][1]?.method).toBe("DELETE");
    expect(String(fetcher.mock.calls[2][0])).toBe("/api/v1/settings/audit-capture");
  });

  it("loads, saves, resets and shows a rejected value", async () => {
    const saved = captureView({ source: "saved", updated_ns: "1800000000000000000", settings: { commit_retries: 0 } });
    const rejected = { error: { code: "invalid_settings", message: "audit.commit_retries must be between 0 and 5" } };
    const responses = [jsonResponse(captureView()), jsonResponse(saved), jsonResponse(rejected, 400), jsonResponse(captureView())];
    const fetcher = vi.fn<typeof fetch>(async () => responses.shift() ?? jsonResponse({}, 500));
    const client = createApiClient(vi.fn(), fetcher);

    const loaded = await loadCaptureForm(client);
    expect(loaded.view?.source).toBe("file");
    expect(loaded.draft).toEqual({ commit_retries: "3" });
    const loadedHTML = renderToStaticMarkup(<CaptureSettingsBody state={loaded} busy={false} onChange={noop} onSave={noop} onReset={noop} />);
    expect(loadedHTML).toContain('id="capture-commit_retries"');
    // Nothing changed yet: saving is off, and there is nothing to reset.
    expect(loadedHTML).toMatch(/<button[^>]*type="submit"[^>]*disabled=""/);
    expect(loadedHTML).not.toContain(">恢复为配置文件的值</button>");

    const afterSave = await saveCaptureForm(client, { ...loaded, draft: { commit_retries: "0" } });
    expect(JSON.parse(String(fetcher.mock.calls[1][1]?.body))).toEqual({ commit_retries: 0 });
    expect(afterSave.view?.source).toBe("saved");
    expect(afterSave.notice).toContain("已保存");
    const savedHTML = renderToStaticMarkup(<CaptureSettingsBody state={afterSave} busy={false} onChange={noop} onSave={noop} onReset={noop} />);
    expect(savedHTML).toContain("已保存，之后开始的终结提交按新的次数重试");
    expect(savedHTML).toContain(">恢复为配置文件的值</button>");

    // The server refuses the value: its message is shown and the draft kept.
    const afterReject = await saveCaptureForm(client, { ...afterSave, draft: { commit_retries: "7" } });
    expect(JSON.parse(String(fetcher.mock.calls[2][1]?.body))).toEqual({ commit_retries: 7 });
    expect(afterReject.error).toBe("audit.commit_retries must be between 0 and 5");
    expect(afterReject.draft).toEqual({ commit_retries: "7" });
    expect(afterReject.view?.settings.commit_retries).toBe(0);
    const rejectedHTML = renderToStaticMarkup(<CaptureSettingsBody state={afterReject} busy={false} onChange={noop} onSave={noop} onReset={noop} />);
    expect(rejectedHTML).toContain("audit.commit_retries must be between 0 and 5");
    expect(rejectedHTML).not.toContain("已保存");

    const afterReset = await resetCaptureForm(client, afterReject);
    expect(fetcher.mock.calls[3][1]?.method).toBe("DELETE");
    expect(afterReset).toMatchObject({ error: null, notice: "已恢复为配置文件里的值。", draft: { commit_retries: "3" } });
    expect(afterReset.view?.source).toBe("file");
  });

  it("shows a load failure instead of the form, and hides an expired session", async () => {
    const failing = createApiClient(vi.fn(), vi.fn<typeof fetch>(async () => jsonResponse({ error: { message: "audit capture settings are unavailable" } }, 503)));
    const failed = await loadCaptureForm(failing);
    expect(failed).toMatchObject({ view: null, error: "audit capture settings are unavailable" });
    const html = renderToStaticMarkup(<CaptureSettingsBody state={failed} busy={false} onChange={noop} onSave={noop} onReset={noop} />);
    expect(html).toContain("audit capture settings are unavailable");
    expect(html).not.toContain("<form");
    expect(renderToStaticMarkup(<CaptureSettingsBody state={emptyCaptureForm} busy={false} onChange={noop} onSave={noop} onReset={noop} />)).not.toContain("<form");

    const expired = createApiClient(vi.fn(), vi.fn<typeof fetch>(async () => jsonResponse({}, 401)));
    expect((await loadCaptureForm(expired)).error).toBeNull();
    // A write refused because the saved value could not be read.
    const unavailable = createApiClient(vi.fn(), vi.fn<typeof fetch>(async () => jsonResponse({ error: { message: "saved settings could not be read; nothing was saved" } }, 503)));
    const state = { ...emptyCaptureForm, view: captureView(), draft: { commit_retries: "1" } };
    expect((await saveCaptureForm(unavailable, state)).error).toContain("nothing was saved");
    expect((await resetCaptureForm(unavailable, state)).error).toContain("nothing was saved");
  });
});

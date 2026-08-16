/**
 * ui-settings 插件（M2；spec §6.6 + 决策 #5 B）。
 *
 * - 安全：自动锁定（空闲）分钟数（1/5/15/30/60）；生物识别宽限开关
 *   **置灰/预留**（决策 #5 B：M2 只做主密码解锁闭环，Windows Hello 留
 *   M2 后快迭代；`session.unlocked.via=biometric` 接口已预留）；
 * - 同步：BYO URL + 轮询间隔（15s~3600s(1h)）；凭据经 `lk config sync
 *   set` 系统钥匙串（本页只写非敏感配置，`config.json` 热更新）；
 * - 审计保留：默认永久（滚动保留后续版本）；
 * - 主题：暗/浅切换（theme 插件 + preference-store 持久化）。
 */

import { useCallback, useEffect, useState, type ComponentType } from "react";
import type { Context, Plugin } from "@cordisjs/core";
import type { ConfigView } from "../types";
import type { SlotComponentConfig } from "./skeleton";
import { slotComponentConfig } from "./skeleton";

const AUTO_LOCK_OPTIONS = ["1", "5", "15", "30", "60"];
const POLL_OPTIONS = ["15", "30", "60", "300", "900", "3600"];

/** 设置页本体（content 槽位，page=settings）。 */
export function SettingsPage({ ctx }: { ctx: Context }) {
  const toast = ctx.toast;
  const [config, setConfig] = useState<ConfigView | null>(null);
  const [saving, setSaving] = useState(false);

  const load = useCallback(() => {
    void ctx.ipc
      .configGet()
      .then(setConfig)
      .catch(() => setConfig(null));
  }, [ctx]);

  useEffect(() => {
    load();
  }, [load]);

  /** 表单态即 ConfigView：URL/间隔直接改本地态（保存时翻译为 ConfigPatch）。 */
  const patchSync = useCallback(
    (patch: Partial<{ url: string; intervalSecs: number }>) => {
      setConfig((c) =>
        c ? { ...c, sync: { url: patch.url ?? c.sync?.url ?? "", intervalSecs: patch.intervalSecs ?? c.sync?.intervalSecs ?? 60 } } : c,
      );
    },
    [],
  );

  const save = async () => {
    if (!config || saving) return;
    setSaving(true);
    try {
      await ctx.ipc.configSet({
        autoLockMinutes: Number(config.autoLockMinutes),
        syncUrl: config.sync?.url ?? "",
        pollSecs: config.sync?.intervalSecs,
      });
      toast.show("设置已保存（config.json 热更新）");
    } catch {
      toast.show("保存失败，请重试");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div id="page-settings" className="page active">
      <h2 className="pane-title">设置</h2>
      <div className="settings-body">
        <div className="settings-group">
          <div className="settings-group-title">安全</div>
          <div className="setting-row">
            <div>
              <div className="setting-label">自动锁定（空闲）</div>
              <div className="setting-desc">锁屏或超时后自动锁定，密钥从内存擦除</div>
            </div>
            <select
              className="select-input"
              aria-label="自动锁定时间"
              value={config ? String(config.autoLockMinutes) : "5"}
              disabled={!config}
              onChange={(e) => setConfig((c) => (c ? { ...c, autoLockMinutes: Number(e.target.value) } : c))}
            >
              {AUTO_LOCK_OPTIONS.map((v) => (
                <option key={v} value={v}>
                  {v} 分钟
                </option>
              ))}
            </select>
          </div>
          <div className="setting-row">
            <div>
              <div className="setting-label">生物识别宽限（Windows Hello）</div>
              <div className="setting-desc">已信任设备宽限窗口内可直接解锁 · M2 后快迭代提供（接口已预留）</div>
            </div>
            <label className="switch" title="M2 预留（决策 #5 B）">
              <input type="checkbox" checked={false} disabled />
              <span className="track" />
            </label>
          </div>
          <div className="setting-row">
            <div>
              <div className="setting-label">审计日志保留</div>
              <div className="setting-desc">默认永久保留 · 滚动保留将在后续版本提供</div>
            </div>
            <span className="select-input" style={{ display: "inline-block" }}>
              永久
            </span>
          </div>
        </div>

        <div className="settings-group">
          <div className="settings-group-title">同步（BYO 存储）</div>
          <div className="setting-row">
            <div>
              <div className="setting-label">存储地址</div>
              <div className="setting-desc">WebDAV / S3 · 存储端只见密文 · 凭据经 lk config sync set 配置（系统钥匙串）</div>
            </div>
            <input
              className="select-input"
              style={{ width: 280 }}
              aria-label="同步存储地址"
              value={config?.sync?.url ?? ""}
              placeholder="webdavs://dav.example.com/lightkey"
              onChange={(e) => patchSync({ url: e.target.value })}
            />
          </div>
          <div className="setting-row">
            <div>
              <div className="setting-label">轮询间隔</div>
              <div className="setting-desc">变更发现靠轮询（无推送）：15s ~ 3600s（1h）</div>
            </div>
            <select
              className="select-input"
              aria-label="同步轮询间隔"
              value={config ? String(config.sync?.intervalSecs ?? 60) : "60"}
              disabled={!config}
              onChange={(e) => patchSync({ intervalSecs: Number(e.target.value) })}
            >
              {POLL_OPTIONS.map((v) => (
                <option key={v} value={v}>
                  {v} 秒
                </option>
              ))}
            </select>
          </div>
          <div className="setting-row">
            <div>
              <div className="setting-label">保存</div>
              <div className="setting-desc">写入 config.json（守护进程热更新）</div>
            </div>
            <button className="btn btn-primary btn-sm" disabled={!config || saving} onClick={() => void save()}>
              {saving ? "保存中…" : "保存"}
            </button>
          </div>
        </div>

        <div className="settings-group">
          <div className="settings-group-title">外观</div>
          <div className="setting-row">
            <div>
              <div className="setting-label">主题</div>
              <div className="setting-desc">设计 tokens 暗/浅两套 · 偏好持久化</div>
            </div>
            <select
              className="select-input"
              aria-label="主题"
              value={ctx.theme.current}
              onChange={(e) => ctx.theme.set(e.target.value as "dark" | "light")}
            >
              <option value="dark">暗色</option>
              <option value="light">浅色</option>
            </select>
          </div>
        </div>
      </div>
    </div>
  );
}

/** 插件工厂：注册 content 槽位组件（page=settings）。 */
export const uiSettings: Plugin.Function<Context, SlotComponentConfig> = Object.assign(
  (ctx: Context, config: SlotComponentConfig) => {
    ctx.slots.register({
      name: "ui-settings",
      slot: config.slot ?? "content",
      order: config.order ?? 30,
      component: (() => {
        const Comp = () => <SettingsPage ctx={ctx} />;
        Comp.slot = "content";
        return Comp as ComponentType<Record<string, unknown>>;
      })(),
      meta: { page: "settings" },
    });
  },
  {
    inject: ["slots", "ipc", "toast", "theme"],
    Config: (raw: unknown) => slotComponentConfig(raw as Parameters<typeof slotComponentConfig>[0]),
  },
);

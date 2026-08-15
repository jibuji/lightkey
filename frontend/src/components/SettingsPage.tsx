/**
 * 设置页（spec §6.6，M2 骨架）：安全 / 同步（BYO）/ 审计保留三组。
 * 页面结构 + 控件形态即可；真实持久化在 M2（走 lk config / 守护进程）。
 */

import { useState } from "react";
import { useToast } from "./Toast";

interface SettingsForm {
  autoLockMin: string;
  bioGrace: boolean;
  syncUrl: string;
  pollSec: string;
}

export function SettingsPage() {
  const { toast } = useToast();
  const [form, setForm] = useState<SettingsForm>({
    autoLockMin: "5",
    bioGrace: true,
    syncUrl: "webdavs://dav.example.com/lightkey",
    pollSec: "60",
  });

  const patch = (p: Partial<SettingsForm>) => {
    setForm((f) => ({ ...f, ...p }));
    toast("设置已保存", "ok");
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
              value={form.autoLockMin}
              onChange={(e) => patch({ autoLockMin: e.target.value })}
            >
              {["1", "5", "15", "30", "60"].map((v) => (
                <option key={v}>{v} 分钟</option>
              ))}
            </select>
          </div>
          <div className="setting-row">
            <div>
              <div className="setting-label">生物识别宽限（Windows Hello）</div>
              <div className="setting-desc">已信任设备宽限窗口内可直接解锁</div>
            </div>
            <label className="switch">
              <input
                type="checkbox"
                checked={form.bioGrace}
                onChange={(e) => patch({ bioGrace: e.target.checked })}
              />
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
              <div className="setting-desc">WebDAV / S3 · 存储端只见密文</div>
            </div>
            <input
              className="select-input"
              style={{ width: 260 }}
              value={form.syncUrl}
              onChange={(e) => patch({ syncUrl: e.target.value })}
            />
          </div>
          <div className="setting-row">
            <div>
              <div className="setting-label">轮询间隔</div>
              <div className="setting-desc">变更发现靠轮询（无推送）：15s ~ 24h</div>
            </div>
            <select
              className="select-input"
              value={form.pollSec}
              onChange={(e) => patch({ pollSec: e.target.value })}
            >
              {["15", "30", "60", "300", "900", "3600"].map((v) => (
                <option key={v}>{v} 秒</option>
              ))}
            </select>
          </div>
        </div>
      </div>
    </div>
  );
}

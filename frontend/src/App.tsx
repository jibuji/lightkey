/**
 * LightKey 桌面应用前端 —— M0 骨架占位页。
 *
 * 仅用于验证 Tauri 壳与前端构建链路；真实界面在 M2 里程碑实现，
 * 设计规格与可交互高保真原型见 docs/design/。
 */
export default function App() {
  return (
    <main className="shell">
      <div className="brand-mark" aria-hidden="true">
        LK
      </div>
      <h1 className="brand-name">LightKey</h1>
      <p className="tagline">轻钥 —— 个人密钥 / 私密信息管理</p>
      <p className="skeleton-note">
        前端骨架已就绪。V1 界面在 M2 里程碑实现；
        设计规格与可交互原型见 <code>docs/design/</code>。
      </p>
    </main>
  );
}

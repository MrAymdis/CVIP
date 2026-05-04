'use client';

import { useState, useEffect } from "react";
import { Bell, Mail, MessageSquare, Smartphone, CheckCircle2, AlertCircle } from "lucide-react";

interface SubscriptionConfig {
  wechat_webhook: string;
  dingtalk_webhook: string;
  email: string;
  severity_threshold: string;
  enabled: boolean;
}

export default function SubscriptionPage() {
  const [config, setConfig] = useState<SubscriptionConfig>({
    wechat_webhook: "",
    dingtalk_webhook: "",
    email: "",
    severity_threshold: "high",
    enabled: false,
  });
  const [isSaving, setIsSaving] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  useEffect(() => {
    loadConfig();
  }, []);

  const loadConfig = async () => {
    try {
      const response = await fetch("/api/v1/subscription");
      if (response.ok) {
        const data = await response.json();
        setConfig(data);
      }
    } catch (error) {
      console.error("Failed to load config:", error);
    }
  };

  const handleSave = async () => {
    setIsSaving(true);
    setMessage(null);

    try {
      const response = await fetch("/api/v1/subscription", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(config),
      });

      if (response.ok) {
        setMessage({ type: "success", text: "配置保存成功！" });
      } else {
        setMessage({ type: "error", text: "配置保存失败，请重试。" });
      }
    } catch (error) {
      setMessage({ type: "error", text: "网络错误，请重试。" });
    } finally {
      setIsSaving(false);
    }
  };

  const handleTest = async (type: 'wechat' | 'dingtalk' | 'email') => {
    setIsSaving(true);
    setMessage(null);

    try {
      const response = await fetch("/api/v1/subscription/test", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ type, config }),
      });

      if (response.ok) {
        setMessage({ type: "success", text: "测试消息已发送！" });
      } else {
        const data = await response.json();
        setMessage({ type: "error", text: data.detail || "测试失败，请检查配置。" });
      }
    } catch (error) {
      setMessage({ type: "error", text: "网络错误，请重试。" });
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800 py-10">
      <div className="container mx-auto px-4">
        <div className="max-w-4xl mx-auto">
          <div className="mb-8">
            <h1 className="text-3xl font-bold mb-2 flex items-center gap-2">
              <Bell className="h-8 w-8 text-primary" />
              服务订阅
            </h1>
            <p className="text-muted-foreground">
              配置漏洞情报告警推送，支持企业微信、钉钉、邮箱等多种方式
            </p>
          </div>

          {message && (
            <div className={`mb-6 p-4 rounded-lg flex items-center gap-3 ${
              message.type === 'success' 
                ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300' 
                : 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300'
            }`}>
              {message.type === 'success' ? (
                <CheckCircle2 className="h-5 w-5" />
              ) : (
                <AlertCircle className="h-5 w-5" />
              )}
              {message.text}
            </div>
          )}

          <div className="grid gap-6">
            <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border p-6">
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 bg-primary/10 rounded-lg flex items-center justify-center">
                    <CheckCircle2 className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <h2 className="text-lg font-semibold">启用告警</h2>
                    <p className="text-sm text-muted-foreground">开启后将自动推送新漏洞情报</p>
                  </div>
                </div>
                <button
                  onClick={() => setConfig({ ...config, enabled: !config.enabled })}
                  className={`relative inline-flex h-8 w-14 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 ${
                    config.enabled ? 'bg-primary' : 'bg-gray-200 dark:bg-gray-700'
                  }`}
                >
                  <span
                    className={`pointer-events-none inline-block h-7 w-7 transform rounded-full bg-white shadow-lg ring-0 transition duration-200 ease-in-out ${
                      config.enabled ? 'translate-x-6' : 'translate-x-0'
                    }`}
                  />
                </button>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium mb-2">告警级别阈值</label>
                  <select
                    value={config.severity_threshold}
                    onChange={(e) => setConfig({ ...config, severity_threshold: e.target.value })}
                    className="w-full px-4 py-2 rounded-lg border bg-white dark:bg-slate-900 focus:outline-none focus:ring-2 focus:ring-primary"
                  >
                    <option value="critical">仅严重 (CRITICAL)</option>
                    <option value="high">高及以上 (HIGH+)</option>
                    <option value="medium">中及以上 (MEDIUM+)</option>
                    <option value="low">全部级别</option>
                  </select>
                </div>
              </div>
            </div>

            <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border p-6">
              <div className="flex items-center gap-3 mb-6">
                <div className="w-10 h-10 bg-green-100 dark:bg-green-900/30 rounded-lg flex items-center justify-center">
                  <Smartphone className="h-5 w-5 text-green-600 dark:text-green-400" />
                </div>
                <div>
                  <h2 className="text-lg font-semibold">企业微信</h2>
                  <p className="text-sm text-muted-foreground">通过企业微信群机器人推送告警</p>
                </div>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium mb-2">Webhook 地址</label>
                  <input
                    type="text"
                    value={config.wechat_webhook}
                    onChange={(e) => setConfig({ ...config, wechat_webhook: e.target.value })}
                    placeholder="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=..."
                    className="w-full px-4 py-2 rounded-lg border bg-white dark:bg-slate-900 focus:outline-none focus:ring-2 focus:ring-primary"
                  />
                </div>
                <button
                  onClick={() => handleTest('wechat')}
                  disabled={!config.wechat_webhook || isSaving}
                  className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  测试推送
                </button>
              </div>
            </div>

            <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border p-6">
              <div className="flex items-center gap-3 mb-6">
                <div className="w-10 h-10 bg-blue-100 dark:bg-blue-900/30 rounded-lg flex items-center justify-center">
                  <MessageSquare className="h-5 w-5 text-blue-600 dark:text-blue-400" />
                </div>
                <div>
                  <h2 className="text-lg font-semibold">钉钉</h2>
                  <p className="text-sm text-muted-foreground">通过钉钉群机器人推送告警</p>
                </div>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium mb-2">Webhook 地址</label>
                  <input
                    type="text"
                    value={config.dingtalk_webhook}
                    onChange={(e) => setConfig({ ...config, dingtalk_webhook: e.target.value })}
                    placeholder="https://oapi.dingtalk.com/robot/send?access_token=..."
                    className="w-full px-4 py-2 rounded-lg border bg-white dark:bg-slate-900 focus:outline-none focus:ring-2 focus:ring-primary"
                  />
                </div>
                <button
                  onClick={() => handleTest('dingtalk')}
                  disabled={!config.dingtalk_webhook || isSaving}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  测试推送
                </button>
              </div>
            </div>

            <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border p-6">
              <div className="flex items-center gap-3 mb-6">
                <div className="w-10 h-10 bg-purple-100 dark:bg-purple-900/30 rounded-lg flex items-center justify-center">
                  <Mail className="h-5 w-5 text-purple-600 dark:text-purple-400" />
                </div>
                <div>
                  <h2 className="text-lg font-semibold">邮箱</h2>
                  <p className="text-sm text-muted-foreground">通过邮件推送告警</p>
                </div>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium mb-2">邮箱地址</label>
                  <input
                    type="email"
                    value={config.email}
                    onChange={(e) => setConfig({ ...config, email: e.target.value })}
                    placeholder="your@email.com"
                    className="w-full px-4 py-2 rounded-lg border bg-white dark:bg-slate-900 focus:outline-none focus:ring-2 focus:ring-primary"
                  />
                </div>
                <button
                  onClick={() => handleTest('email')}
                  disabled={!config.email || isSaving}
                  className="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  测试推送
                </button>
              </div>
            </div>

            <div className="flex justify-end">
              <button
                onClick={handleSave}
                disabled={isSaving}
                className="px-6 py-3 bg-primary hover:bg-primary/90 text-white rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isSaving ? "保存中..." : "保存配置"}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

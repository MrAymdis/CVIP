import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class NotificationService:
    @staticmethod
    def send_wechat_webhook(webhook_url: str, title: str, content: str) -> bool:
        """Send message to WeChat Work webhook."""
        try:
            message = {
                "msgtype": "markdown",
                "markdown": {
                    "content": f"## {title}\n\n{content}"
                }
            }
            response = requests.post(webhook_url, json=message, timeout=10)
            response.raise_for_status()
            result = response.json()
            if result.get("errcode") == 0:
                logger.info("WeChat notification sent successfully")
                return True
            else:
                logger.error(f"WeChat notification failed: {result}")
                return False
        except Exception as e:
            logger.error(f"Failed to send WeChat notification: {e}")
            return False

    @staticmethod
    def send_dingtalk_webhook(webhook_url: str, title: str, content: str) -> bool:
        """Send message to DingTalk webhook."""
        try:
            message = {
                "msgtype": "markdown",
                "markdown": {
                    "title": title,
                    "text": f"### {title}\n\n{content}"
                }
            }
            response = requests.post(webhook_url, json=message, timeout=10)
            response.raise_for_status()
            result = response.json()
            if result.get("errcode") == 0:
                logger.info("DingTalk notification sent successfully")
                return True
            else:
                logger.error(f"DingTalk notification failed: {result}")
                return False
        except Exception as e:
            logger.error(f"Failed to send DingTalk notification: {e}")
            return False

    @staticmethod
    def send_email(to_email: str, title: str, content: str, smtp_host: Optional[str] = None, 
                   smtp_port: Optional[int] = None, smtp_user: Optional[str] = None, 
                   smtp_password: Optional[str] = None) -> bool:
        """Send email notification."""
        try:
            msg = MIMEMultipart()
            msg['From'] = smtp_user or 'notification@vuln-intel.local'
            msg['To'] = to_email
            msg['Subject'] = title

            msg.attach(MIMEText(content, 'plain', 'utf-8'))

            # If SMTP settings are provided, use them; otherwise, just log
            if smtp_host and smtp_port:
                with smtplib.SMTP(smtp_host, smtp_port) as server:
                    if smtp_user and smtp_password:
                        server.starttls()
                        server.login(smtp_user, smtp_password)
                    server.send_message(msg)
                logger.info("Email notification sent successfully")
            else:
                logger.info(f"Email notification would be sent to {to_email} (SMTP not configured)")
                logger.info(f"Subject: {title}")
                logger.info(f"Content: {content}")
            return True
        except Exception as e:
            logger.error(f"Failed to send email notification: {e}")
            return False

    @staticmethod
    def send_test_message(channel_type: str, config: dict) -> bool:
        """Send a test message to the specified channel."""
        title = "测试消息 - 漏洞情报平台"
        content = (
            "这是一条测试消息，来自漏洞情报平台服务订阅功能。\n\n"
            "如果您收到了这条消息，说明您的配置是正确的！\n\n"
            "配置的告警级别阈值: " + config.get("severity_threshold", "high")
        )

        if channel_type == "wechat" and config.get("wechat_webhook"):
            return NotificationService.send_wechat_webhook(config["wechat_webhook"], title, content)
        elif channel_type == "dingtalk" and config.get("dingtalk_webhook"):
            return NotificationService.send_dingtalk_webhook(config["dingtalk_webhook"], title, content)
        elif channel_type == "email" and config.get("email"):
            return NotificationService.send_email(config["email"], title, content)
        else:
            logger.error(f"Invalid channel type or missing configuration: {channel_type}")
            return False

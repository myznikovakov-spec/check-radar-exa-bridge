"use strict";

const { classifyResponse } = require("./challenge-detector");

/**
 * Step 3: unified safe reaction to access checks.
 *
 * This handler does not bypass or solve challenges.
 * Any non-ALLOW detector result stops automation and requests notification.
 */
function handleAccessCheck(input = {}) {
  const detection = classifyResponse(input);

  if (detection.decision === "ALLOW") {
    return {
      stop: false,
      action: "CONTINUE",
      notify: false,
      detection
    };
  }

  const host = (() => {
    try {
      return new URL(String(input.url || "")).host || "unknown";
    } catch {
      return "unknown";
    }
  })();

  return {
    stop: true,
    action: "STOP",
    notify: true,
    notification: {
      level: "warning",
      code: "ACCESS_CHECK_DETECTED",
      title_ru: "Требуется проверка доступа",
      message_ru:
        `Автоматика остановлена для ${host}. Причина: ${detection.category}. ` +
        (detection.manual_check_required
          ? "Нужна ручная проверка."
          : "Повторные запросы пока не выполняем."),
      url: String(input.url || ""),
      provider: detection.provider,
      category: detection.category,
      http_status: detection.http_status,
      retry_after: detection.retry_after
    },
    detection
  };
}

module.exports = { handleAccessCheck };

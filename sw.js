const ICON_DATA_URL = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAACXBIWXMAAAsTAAALEwEAmpwYAAABlElEQVR4nO2YsUoDQRBGH1mCHkCiCdwFIQFJq8D0DewAkQC7AMlBzADpARKCiYUZYnOxPpbmvuYt3Nv7uzss3mZ3dx87vPTmBq1Wq1Wq9VD8WxSMVjVdAUj1DjEaZJgFZ4BoJ5MGgN6Xk0kA7MBJY6Ue4Io6WSAWfQk4DaNkMgJkqI4HHhBQwfwWEMoq6LghT1J4E6Gyl20y1mo2bF3S2KfApDmFA8uQbIoJb5U3Uuhm9E33XxGpI0pBDNlhp3tIop3s0zNdCq4kAvG5JH0jox1WSYE4i8XbRFWKIRXWi7DWrBL1QkYF0rhqYpFiGYs0NmtjBBs8c6R+SYG2sUssg9u6etvMg+u/Akkp4oPxFhXzUu57XLQz4YfslZrTf7o5Qx/QuCnvI58Vw+dQkifY0mKVyLDmkOMn9otM9EwM8Dzv4v9fRAT1/FeKUJQuuNcI7Ii1XjSrX3/4qixRKImKkbiNHjK80TFIlIp6LSfpnt+A1HhZMVkJTLgAAAABJRU5ErkJggg==";

self.addEventListener("install", (event) => {
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      await clients.claim();

      // Re-register subscription with server on activation (browser restart recovery)
      try {
        let subscription = await self.registration.pushManager.getSubscription();

        // If subscription was lost (browser restart), we can't recreate it here
        // because we don't have applicationServerKey. The page will handle it.
        // But if it exists, re-register it.
        if (subscription) {
          console.log("[SW] Re-registering existing subscription on activate");
          await fetch("/api/subscribe", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ subscription: subscription.toJSON() }),
          });
        } else {
          console.log("[SW] No subscription on activate - page will handle re-subscription");
        }
      } catch (err) {
        console.error("[SW] Failed to re-register on activate:", err);
      }
    })()
  );
});

self.addEventListener("push", (event) => {
  console.log("[SW] Push event received!", event);

  let data = { title: "Push Demo", body: "Message received", url: "/" };
  if (event.data) {
    try {
      data = event.data.json();
      console.log("[SW] Push data parsed:", data);
    } catch (err) {
      console.log("[SW] Push data as text:", event.data.text());
      data.body = event.data.text();
    }
  } else {
    console.log("[SW] Push event had no data");
  }

  event.waitUntil(
    (async () => {
      const options = {
        body: data.body,
        icon: data.icon || ICON_DATA_URL,  // Use custom icon if provided
        badge: ICON_DATA_URL,
        data: { url: data.url || "/" },
        // Add these to help ensure notification shows
        requireInteraction: false,
        silent: false,
        tag: "push-" + Date.now(), // Unique tag prevents collapsing
      };

      console.log("[SW] Showing notification:", data.title, options);

      try {
        await self.registration.showNotification(data.title || "Push Demo", options);
        console.log("[SW] Notification shown successfully");
      } catch (err) {
        console.error("[SW] showNotification failed:", err);
      }

      const clientList = await clients.matchAll({ type: "window", includeUncontrolled: true });
      console.log("[SW] Posting to", clientList.length, "clients");
      clientList.forEach((client) =>
        client.postMessage({ type: "push-received", data, at: new Date().toISOString() })
      );
    })()
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  if (event.action === "close") return;

  event.waitUntil(
    (async () => {
      const targetUrl = event.notification.data?.url || "/";
      await clients.openWindow(targetUrl);
      try {
        const sub = await self.registration.pushManager.getSubscription();
        if (sub?.endpoint) {
          await fetch("/api/telemetry", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ endpoint: sub.endpoint }),
          });
        }
      } catch (err) {
        console.error("[telemetry]", err);
      }
    })()
  );
});

self.addEventListener("message", (event) => {
  if (event.data?.type === "simulate-push") {
    const data = event.data.payload || { title: "Simulated", body: "hello", url: "/" };
    self.registration.showNotification(data.title, {
      body: data.body,
      icon: ICON_DATA_URL,
      data: { url: data.url },
    });
  }

  // Manual keepalive trigger from page
  if (event.data?.type === "keepalive") {
    sendKeepalive();
  }
});

// Periodic background sync (if supported) - keeps subscription fresh
self.addEventListener("periodicsync", (event) => {
  if (event.tag === "push-keepalive") {
    event.waitUntil(sendKeepalive());
  }
});

// Keepalive function - re-registers subscription to update last_seen
async function sendKeepalive() {
  try {
    const subscription = await self.registration.pushManager.getSubscription();
    if (subscription) {
      const res = await fetch("/api/subscribe", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ subscription: subscription.toJSON() }),
      });
      if (res.ok) {
        console.log("[SW] Keepalive: subscription refreshed");
      }
    }
  } catch (err) {
    console.error("[SW] Keepalive failed:", err);
  }
}

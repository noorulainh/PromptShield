const SESSION_KEY = "promptshield_session_id";
const CHAT_COUNTER_KEY = "promptshield_chat_counter";
const CHAT_ACTIVE_KEY = "promptshield_chat_active";
const CHAT_MAP_KEY = "promptshield_chat_map";

interface ChatMapItem {
  chatId: string;
  sessionId: string;
  createdAt: string;
}


function readChatMap(): ChatMapItem[] {
  if (typeof window === "undefined") {
    return [];
  }
  const raw = localStorage.getItem(CHAT_MAP_KEY);
  if (!raw) {
    return [];
  }
  try {
    const parsed = JSON.parse(raw) as ChatMapItem[];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}


function writeChatMap(items: ChatMapItem[]) {
  if (typeof window === "undefined") {
    return;
  }
  localStorage.setItem(CHAT_MAP_KEY, JSON.stringify(items));
}


function chatIdFromCounter(counter: number) {
  return String(Math.max(1, counter)).padStart(3, "0");
}


function upsertChatMap(chatId: string, sessionId: string) {
  const items = readChatMap();
  const existingIndex = items.findIndex((item) => item.chatId === chatId);
  if (existingIndex >= 0) {
    items[existingIndex] = {
      ...items[existingIndex],
      sessionId,
    };
  } else {
    items.push({
      chatId,
      sessionId,
      createdAt: new Date().toISOString(),
    });
  }
  writeChatMap(items);
}

export function getClientSessionId() {
  if (typeof window === "undefined") {
    return null;
  }
  return localStorage.getItem(SESSION_KEY);
}

export function setClientSessionId(sessionId: string) {
  if (typeof window === "undefined") {
    return;
  }
  localStorage.setItem(SESSION_KEY, sessionId);
  const active = localStorage.getItem(CHAT_ACTIVE_KEY);
  if (active) {
    upsertChatMap(active, sessionId);
  }
}


export function initializeChatSession(sessionId: string) {
  if (typeof window === "undefined") {
    return "001";
  }

  const active = localStorage.getItem(CHAT_ACTIVE_KEY);
  if (active) {
    upsertChatMap(active, sessionId);
    return active;
  }

  const storedCounter = Number(localStorage.getItem(CHAT_COUNTER_KEY) ?? "1");
  const safeCounter = Number.isFinite(storedCounter) && storedCounter > 0 ? Math.floor(storedCounter) : 1;
  const chatId = chatIdFromCounter(safeCounter);

  localStorage.setItem(CHAT_COUNTER_KEY, String(safeCounter));
  localStorage.setItem(CHAT_ACTIVE_KEY, chatId);
  upsertChatMap(chatId, sessionId);
  return chatId;
}


export function startFreshChatSession(sessionId: string) {
  if (typeof window === "undefined") {
    return "001";
  }

  const currentCounter = Number(localStorage.getItem(CHAT_COUNTER_KEY) ?? "1");
  const safeCurrent = Number.isFinite(currentCounter) && currentCounter > 0 ? Math.floor(currentCounter) : 1;
  const nextCounter = safeCurrent + 1;
  const chatId = chatIdFromCounter(nextCounter);

  localStorage.setItem(CHAT_COUNTER_KEY, String(nextCounter));
  localStorage.setItem(CHAT_ACTIVE_KEY, chatId);
  setClientSessionId(sessionId);
  upsertChatMap(chatId, sessionId);
  return chatId;
}


export function getActiveChatId() {
  if (typeof window === "undefined") {
    return null;
  }
  return localStorage.getItem(CHAT_ACTIVE_KEY);
}


export function listChatSessions() {
  return readChatMap();
}


export function findSessionIdByChatId(chatId: string) {
  const item = readChatMap().find((entry) => entry.chatId === chatId);
  return item?.sessionId ?? null;
}


export function resetClientConversationState() {
  if (typeof window === "undefined") {
    return;
  }
  localStorage.removeItem(SESSION_KEY);
  localStorage.removeItem(CHAT_COUNTER_KEY);
  localStorage.removeItem(CHAT_ACTIVE_KEY);
  localStorage.removeItem(CHAT_MAP_KEY);
}

export function getCookie(name: string) {
  if (typeof document === "undefined") {
    return "";
  }
  const cookies = document.cookie.split(";").map((item) => item.trim());
  const found = cookies.find((item) => item.startsWith(`${name}=`));
  return found ? decodeURIComponent(found.split("=")[1]) : "";
}

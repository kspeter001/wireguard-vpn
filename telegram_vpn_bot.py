#!/usr/bin/env python3
"""WireGuard VPN Telegram bot — managed by wireguard-vpn.sh install."""

from __future__ import annotations

import logging
import os
import re
import subprocess
import tempfile
from pathlib import Path

import qrcode
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes

# =========================
# CONFIG (from env / .env file written by installer)
# =========================
BOT_TOKEN = os.environ.get("BOT_TOKEN", "").strip()
AUTHORIZED_RAW = os.environ.get("AUTHORIZED_USER", "").strip()
VPN_CMD = os.environ.get("VPN_CMD", "/usr/local/bin/vpn")
CLIENT_DIR = Path(os.environ.get("CLIENT_DIR", "/etc/wireguard/clients"))
ENDPOINT_FILE = Path(os.environ.get("ENDPOINT_FILE", "/etc/wireguard/server_endpoint"))
WG_IF = os.environ.get("WG_IF", "wg0")

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")

logging.basicConfig(
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    level=logging.INFO,
)
log = logging.getLogger("vpn-bot")


def authorized_ids() -> set[int]:
    ids: set[int] = set()
    for part in AUTHORIZED_RAW.replace(" ", "").split(","):
        if not part:
            continue
        try:
            ids.add(int(part))
        except ValueError:
            log.warning("Ignoring invalid AUTHORIZED_USER entry: %s", part)
    return ids


AUTH_IDS = authorized_ids()


def is_authorized(update: Update) -> bool:
    user = update.effective_user
    return bool(user and user.id in AUTH_IDS)


async def deny(update: Update) -> None:
    if update.message:
        uid = update.effective_user.id if update.effective_user else "?"
        await update.message.reply_text(f"Unauthorized (your id: {uid})")


def run_vpn(*args: str, timeout: int = 60) -> tuple[int, str]:
    cmd = [VPN_CMD, *args]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return 124, "ERROR: command timed out"
    except FileNotFoundError:
        return 127, f"ERROR: missing command {VPN_CMD}"
    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()
    text = out if out else err
    if proc.returncode != 0 and err and out:
        text = f"{out}\n{err}"
    elif proc.returncode != 0 and not text:
        text = f"ERROR: exit code {proc.returncode}"
    return proc.returncode, text


def valid_name(name: str) -> bool:
    return bool(NAME_RE.match(name))


def make_qr_png(conf_path: Path, out_path: Path) -> None:
    data = conf_path.read_text(encoding="utf-8")
    img = qrcode.make(data)
    img.save(out_path)


def chunk_message(text: str, limit: int = 3500) -> list[str]:
    text = text.strip() or "(empty)"
    if len(text) <= limit:
        return [text]
    parts: list[str] = []
    while text:
        parts.append(text[:limit])
        text = text[limit:]
    return parts


async def reply_text(update: Update, text: str) -> None:
    if not update.message:
        return
    for part in chunk_message(text):
        await update.message.reply_text(part)


# =========================
# COMMANDS
# =========================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_authorized(update):
        await deny(update)
        return
    await help_cmd(update, context)


async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_authorized(update):
        await deny(update)
        return
    await update.message.reply_text(
        "VPN Bot commands:\n"
        "/users — list users\n"
        "/add <name> — create user + QR\n"
        "/show <name> — QR again\n"
        "/conf <name> — send .conf file\n"
        "/delete <name> — remove user\n"
        "/online — connected now\n"
        "/status — all users online/offline\n"
        "/server — WireGuard server info\n"
        "/id — your Telegram user id\n"
        "/help — this help"
    )


async def my_id(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    uid = update.effective_user.id if update.effective_user else None
    await update.message.reply_text(f"Your Telegram user id: {uid}")


async def users(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_authorized(update):
        await deny(update)
        return
    code, output = run_vpn("users")
    await reply_text(update, output if code == 0 else f"Failed:\n{output}")


async def add(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_authorized(update):
        await deny(update)
        return
    if not context.args:
        await update.message.reply_text("Usage: /add iphone1")
        return
    name = context.args[0].strip()
    if not valid_name(name):
        await update.message.reply_text("Invalid name. Use letters, numbers, . _ - (max 32)")
        return

    await update.message.reply_text(f"Creating user {name}…")
    code, output = run_vpn("add", name, "--no-qr")
    if code != 0:
        await reply_text(update, f"Failed:\n{output}")
        return

    conf = CLIENT_DIR / f"{name}.conf"
    if not conf.is_file():
        await reply_text(update, f"Created but conf missing:\n{output}")
        return

    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
        qr_path = Path(tmp.name)
    try:
        make_qr_png(conf, qr_path)
        with qr_path.open("rb") as photo:
            await update.message.reply_photo(
                photo=photo,
                caption=f"VPN user created: {name}\n{output}",
            )
        with conf.open("rb") as doc:
            await update.message.reply_document(
                document=doc,
                filename=f"{name}.conf",
                caption=f"{name}.conf — import in WireGuard app",
            )
    finally:
        qr_path.unlink(missing_ok=True)


async def show(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_authorized(update):
        await deny(update)
        return
    if not context.args:
        await update.message.reply_text("Usage: /show iphone1")
        return
    name = context.args[0].strip()
    if not valid_name(name):
        await update.message.reply_text("Invalid name")
        return

    conf = CLIENT_DIR / f"{name}.conf"
    if not conf.is_file():
        await update.message.reply_text("User not found")
        return

    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
        qr_path = Path(tmp.name)
    try:
        make_qr_png(conf, qr_path)
        with qr_path.open("rb") as photo:
            await update.message.reply_photo(photo=photo, caption=f"QR for {name}")
    finally:
        qr_path.unlink(missing_ok=True)


async def conf_file(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_authorized(update):
        await deny(update)
        return
    if not context.args:
        await update.message.reply_text("Usage: /conf iphone1")
        return
    name = context.args[0].strip()
    if not valid_name(name):
        await update.message.reply_text("Invalid name")
        return
    conf = CLIENT_DIR / f"{name}.conf"
    if not conf.is_file():
        await update.message.reply_text("User not found")
        return
    with conf.open("rb") as doc:
        await update.message.reply_document(
            document=doc,
            filename=f"{name}.conf",
            caption=f"Config for {name}",
        )


async def delete(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_authorized(update):
        await deny(update)
        return
    if not context.args:
        await update.message.reply_text("Usage: /delete iphone1")
        return
    name = context.args[0].strip()
    if not valid_name(name):
        await update.message.reply_text("Invalid name")
        return
    code, output = run_vpn("delete", name)
    await reply_text(update, output if code == 0 else f"Failed:\n{output}")


async def online(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_authorized(update):
        await deny(update)
        return
    code, output = run_vpn("online")
    await reply_text(update, output if code == 0 else f"Failed:\n{output}")


async def status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_authorized(update):
        await deny(update)
        return
    code, output = run_vpn("status")
    await reply_text(update, output if code == 0 else f"Failed:\n{output}")


async def server(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_authorized(update):
        await deny(update)
        return
    code, output = run_vpn("server")
    await reply_text(update, output if code == 0 else f"Failed:\n{output}")


def main() -> None:
    if not BOT_TOKEN:
        raise SystemExit("BOT_TOKEN is not set")
    if not AUTH_IDS:
        raise SystemExit("AUTHORIZED_USER is not set")

    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("id", my_id))
    app.add_handler(CommandHandler("users", users))
    app.add_handler(CommandHandler("add", add))
    app.add_handler(CommandHandler("show", show))
    app.add_handler(CommandHandler("conf", conf_file))
    app.add_handler(CommandHandler("delete", delete))
    app.add_handler(CommandHandler("online", online))
    app.add_handler(CommandHandler("status", status))
    app.add_handler(CommandHandler("server", server))

    log.info("VPN Telegram bot starting (authorized ids: %s)", sorted(AUTH_IDS))
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()

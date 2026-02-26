import asyncio
import json
import logging
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple

try:
    import tomllib
except ModuleNotFoundError:
    tomllib = None


@dataclass
class BackendRoute:
    status_host: str
    status_port: int
    transfer_host: str
    transfer_port: int


@dataclass
class AppConfig:
    listen_host: str
    listen_port: int
    routes: Dict[str, BackendRoute]


def read_varint_from_buffer(buf: bytes, offset: int = 0) -> Tuple[int, int]:
    value = 0
    shift = 0
    pos = offset
    for _ in range(5):
        if pos >= len(buf):
            raise ValueError("VarInt 读取失败：数据不足")
        current = buf[pos]
        pos += 1
        value |= (current & 0x7F) << shift
        if (current & 0x80) == 0:
            if value & (1 << 31):
                value -= 1 << 32
            return value, pos
        shift += 7
    raise ValueError("VarInt 过长")


def write_varint(value: int) -> bytes:
    if value < 0:
        value &= 0xFFFFFFFF
    output = bytearray()
    while True:
        temp = value & 0x7F
        value >>= 7
        if value:
            output.append(temp | 0x80)
        else:
            output.append(temp)
            break
    return bytes(output)


def read_string_from_buffer(buf: bytes, offset: int = 0) -> Tuple[str, int]:
    strlen, offset = read_varint_from_buffer(buf, offset)
    if strlen < 0:
        raise ValueError("字符串长度非法")
    end = offset + strlen
    if end > len(buf):
        raise ValueError("字符串读取失败：数据不足")
    return buf[offset:end].decode("utf-8", errors="replace"), end


def write_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return write_varint(len(encoded)) + encoded


async def read_varint(reader: asyncio.StreamReader) -> int:
    value = 0
    shift = 0
    while True:
        b = await reader.readexactly(1)
        current = b[0]
        value |= (current & 0x7F) << shift
        if (current & 0x80) == 0:
            if value & (1 << 31):
                value -= 1 << 32
            return value
        shift += 7


async def read_packet(reader: asyncio.StreamReader) -> Tuple[int, bytes]:
    packet_length = await read_varint(reader)
    payload = await reader.readexactly(packet_length)
    packet_id, offset = read_varint_from_buffer(payload, 0)
    return packet_id, payload[offset:]


async def send_packet(writer: asyncio.StreamWriter, packet_id: int, body: bytes) -> None:
    payload = write_varint(packet_id) + body
    writer.write(write_varint(len(payload)) + payload)
    await writer.drain()


def parse_route(route_obj: dict) -> BackendRoute:
    status = route_obj["status"]
    transfer = route_obj.get("transfer", status)
    return BackendRoute(
        status_host=str(status["host"]),
        status_port=int(status["port"]),
        transfer_host=str(transfer["host"]),
        transfer_port=int(transfer["port"]),
    )


def load_config(path: str = "config.toml") -> AppConfig:
    parser = tomllib
    if parser is None:
        import importlib

        parser = importlib.import_module("tomli")

    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"配置文件不存在: {config_path}")

    data = parser.loads(config_path.read_text(encoding="utf-8"))

    proxy = data.get("proxy", {})
    listen_host = str(proxy.get("listen_host", "0.0.0.0"))
    listen_port = int(proxy.get("listen_port", 25565))

    routes_obj = data.get("routes", {})
    routes: Dict[str, BackendRoute] = {}
    for domain, route_obj in routes_obj.items():
        routes[domain.strip().lower()] = parse_route(route_obj)

    return AppConfig(
        listen_host=listen_host,
        listen_port=listen_port,
        routes=routes,
    )


class DomainTransferProxy:
    def __init__(self, cfg: AppConfig):
        self.cfg = cfg
        self.logger = logging.getLogger("domain-transfer-proxy")

    def resolve_route(self, host: str) -> Optional[BackendRoute]:
        key = host.strip().rstrip(".").lower()
        return self.cfg.routes.get(key)

    async def fetch_backend_status(self, route: BackendRoute, protocol_version: int) -> dict:
        return await self._query_backend_status(route.status_host, route.status_port, protocol_version)

    async def _query_backend_status(self, host: str, port: int, protocol_version: int) -> dict:
        reader, writer = await asyncio.open_connection(host, port)
        try:
            handshake_body = (
                write_varint(protocol_version)
                + write_string(host)
                + struct.pack(">H", port)
                + write_varint(1)
            )
            await send_packet(writer, 0x00, handshake_body)
            await send_packet(writer, 0x00, b"")

            packet_id, body = await read_packet(reader)
            if packet_id != 0x00:
                raise ValueError(f"后端状态包ID异常: {packet_id}")

            status_json, _ = read_string_from_buffer(body, 0)
            return json.loads(status_json)
        finally:
            writer.close()
            await writer.wait_closed()

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        try:
            packet_id, body = await read_packet(reader)
            if packet_id != 0x00:
                return

            protocol_version, offset = read_varint_from_buffer(body, 0)
            server_address, offset = read_string_from_buffer(body, offset)
            if offset + 2 > len(body):
                return
            _server_port = struct.unpack(">H", body[offset:offset + 2])[0]
            offset += 2
            next_state, _ = read_varint_from_buffer(body, offset)

            original_host = server_address.split("\x00", 1)[0].strip()
            route = self.resolve_route(original_host)
            if route is None:
                self.logger.info("未匹配域名，静默断开: %s from %s", original_host, peer)
                return

            if next_state == 1:
                await self.handle_status(reader, writer, route, protocol_version)
            elif next_state in (2, 3):
                await self.handle_login_then_transfer(reader, writer, route)
            else:
                self.logger.info("未知状态切换值: %s from %s", next_state, peer)
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception:
            self.logger.exception("处理连接失败: %s", peer)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def handle_status(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        route: BackendRoute,
        protocol_version: int,
    ) -> None:
        request_id, _ = await read_packet(reader)
        if request_id != 0x00:
            return

        try:
            status_obj = await self.fetch_backend_status(route, protocol_version)
        except Exception as exc:
            self.logger.warning("后端状态查询失败: %s", exc)
            status_obj = {
                "version": {"name": "Unknown", "protocol": protocol_version},
                "players": {"max": 0, "online": 0, "sample": []},
                "description": {"text": "后端离线或不可达"},
            }

        status_json = json.dumps(status_obj, ensure_ascii=False, separators=(",", ":"))
        await send_packet(writer, 0x00, write_string(status_json))

        try:
            ping_id, ping_body = await read_packet(reader)
            if ping_id == 0x01 and len(ping_body) == 8:
                await send_packet(writer, 0x01, ping_body)
        except asyncio.IncompleteReadError:
            return

    async def handle_login_then_transfer(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        route: BackendRoute,
    ) -> None:
        login_start_id, login_body = await read_packet(reader)
        if login_start_id != 0x00:
            await self.send_disconnect(writer, "登录流程异常")
            return

        username = "Player"
        try:
            username, _ = read_string_from_buffer(login_body, 0)
        except Exception:
            pass

        fake_uuid = self.make_offline_uuid(username)

        # Login Success (Login state, clientbound 0x02)
        login_success_body = fake_uuid + write_string(username) + write_varint(0)
        await send_packet(writer, 0x02, login_success_body)

        # 等待 Login Acknowledged (serverbound 0x03)
        ack_id, _ = await read_packet(reader)
        if ack_id != 0x03:
            await self.send_config_disconnect(writer, "客户端未完成登录确认")
            return

        # Configuration Transfer (Configuration state, clientbound 0x0B)
        transfer_body = write_string(route.transfer_host) + write_varint(route.transfer_port)
        await send_packet(writer, 0x0B, transfer_body)

    async def send_disconnect(self, writer: asyncio.StreamWriter, text: str) -> None:
        reason = json.dumps({"text": text}, ensure_ascii=False)
        await send_packet(writer, 0x00, write_string(reason))

    async def send_config_disconnect(self, writer: asyncio.StreamWriter, text: str) -> None:
        reason = json.dumps({"text": text}, ensure_ascii=False)
        await send_packet(writer, 0x02, write_string(reason))

    @staticmethod
    def make_offline_uuid(username: str) -> bytes:
        import hashlib

        data = f"OfflinePlayer:{username}".encode("utf-8")
        md5 = bytearray(hashlib.md5(data).digest())
        md5[6] = (md5[6] & 0x0F) | 0x30
        md5[8] = (md5[8] & 0x3F) | 0x80
        return bytes(md5)


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s %(message)s")
    cfg = load_config("config.toml")
    proxy = DomainTransferProxy(cfg)

    server = await asyncio.start_server(proxy.handle_client, cfg.listen_host, cfg.listen_port)
    addrs = ", ".join(str(sock.getsockname()) for sock in (server.sockets or []))
    logging.info("Domain Transfer Proxy 启动: %s", addrs)

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())

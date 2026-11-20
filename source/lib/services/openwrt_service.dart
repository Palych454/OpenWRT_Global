import 'dart:async';
import 'dart:convert';
import 'dart:io' show IOSink;
import 'dart:typed_data';
import 'package:dartssh2/dartssh2.dart';
import '../models/router_connection.dart';
import '../models/system_info.dart';
import '../models/wifi_info.dart';
import '../models/client_info.dart';
import '../models/package_info.dart';
import '../models/network_info.dart';
import '../models/vpn_info.dart';
import '../models/channel_scan_result.dart';
import '../models/openwrt_capabilities.dart';
import 'app_logger.dart';
import 'storage_service.dart';

class OpenWrtService {
  final RouterConnection config;

  /// Колбэк проверки host key при первом подключении к новому хосту.
  /// Получает fingerprint (например "SHA256:..."), возвращает true — принять.
  /// Если null — проверка пропускается (для совместимости).
  Future<bool> Function(String fingerprint)? onVerifyHostKey;

  /// Вызывается после того, как пользователь принял fingerprint нового хоста.
  /// Позволяет сохранить его в настройках роутера.
  Future<void> Function(String fingerprint)? onFingerprintAccepted;

  /// Кэшированные возможности OpenWrt (определяются при первом подключении).
  OpenWrtCapabilities? _capabilities;

  /// Кэш счётчиков для расчёта скорости WAN: хост -> (rx_bytes, время, tx_bytes).
  final Map<String, (int, DateTime, int)> _wanStats = {};

  static Map<String, bool> lastDepsStatus = {};
  SSHClient? _client;
  bool _connected = false;
  Timer? _keepAliveTimer;
  Future<void> _queue = Future.value();
  Future<void>? _connecting;

  OpenWrtService(this.config);

  String _readableError(Object error) {
    return error
        .toString()
        .replaceAll(config.password, '***')
        .replaceAll(RegExp(r'[\u0000-\u001F\u007F]'), ' ')
        .replaceAll(RegExp(r'\s+'), ' ')
        .trim();
  }

  bool get isConnected => _connected;

  SSHClient? get sshClient => _client;

  /// Последовательное выполнение задач — исключает гонки за SSH-сессией.
  /// dartssh2 не допускает параллельных вызовов `run()`, из-за чего канал
  /// обрывался при одновременном поллинге экранов и keepalive.
  Future<T> _enqueue<T>(Future<T> Function() task) {
    final result = _queue.then((_) => task());
    _queue = result.then((_) {}, onError: (_) {});
    return result;
  }

  Future<void> connect() {
    return _enqueue(_connectInternal);
  }

  Future<void> _connectInternal() async {
    if (_connected && _client != null) return;
    if (_connecting != null) return _connecting!;
    final f = () async {
      // Сначала основной адрес, затем запасной (идея из luci-mobile):
      // удобно, когда вы не в домашней сети — DDNS/внешний IP/другой порт.
      final hosts = <String>[config.host];
      final alt = config.host2?.trim();
      if (alt != null && alt.isNotEmpty && alt != config.host) hosts.add(alt);
      Object? lastError;
      for (final host in hosts) {
        try {
          await _establish(host);
          return;
        } catch (e) {
          lastError = e;
        }
      }
      _connected = false;
      AppLogger.e('SSH connect failed to ${config.host}', lastError!);
      throw Exception('Ошибка подключения SSH: ${_readableError(lastError)}');
    }();
    _connecting = f;
    try {
      await f;
    } finally {
      _connecting = null;
    }
  }

  Future<void> _establish(String host) async {
    _client = null;
    _connected = false;
    final socket = await SSHSocket.connect(host, config.port)
        .timeout(const Duration(seconds: 15));
    // Проверка fingerprint хоста (MITM-защита).
    final verify = onVerifyHostKey;
    final accepted = onFingerprintAccepted;
    FutureOr<bool> Function(String type, Uint8List fpBytes)? onVerify;
    if (verify != null) {
      onVerify = (String type, Uint8List fpBytes) async {
        String fp;
        try {
          fp = utf8.decode(fpBytes);
        } catch (_) {
          fp = fpBytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join(':');
        }
        // Отпечаток, сохранённый для ЭТОГО хоста (основного или запасного) —
        // сверяем сами, чтобы не переспрашивать пользователя.
        final stored = await StorageService.loadFingerprint(host);
        if (stored != null && stored.isNotEmpty) return stored == fp;
        // Если ожидаем конкретный fingerprint из конфига — сверяем строго.
        if (config.fingerprint != null && config.fingerprint!.isNotEmpty) {
          if (fp == config.fingerprint) return true;
        }
        // Иначе спрашиваем пользователя.
        final ok = await verify(fp);
        if (ok) {
          await StorageService.saveFingerprint(host, fp);
          if (accepted != null) await accepted(fp);
        }
        return ok;
      };
    }
    if (config.useKey && config.sshKey != null && config.sshKey!.isNotEmpty) {
      final keyPairs = SSHKeyPair.fromPem(config.sshKey!);
      _client = SSHClient(
        socket,
        username: config.username,
        identities: keyPairs,
        onPasswordRequest: () => null,
        onVerifyHostKey: onVerify,
      );
    } else {
      _client = SSHClient(
        socket,
        username: config.username,
        onPasswordRequest: () => config.password,
        onVerifyHostKey: onVerify,
      );
    }
    await _client!.authenticated.timeout(const Duration(seconds: 15));
    await _client!.run('echo ok').timeout(const Duration(seconds: 15));
    _startKeepAlive();
    _connected = true;
    AppLogger.i('SSH connected to $host:${config.port}');
  }

  void _startKeepAlive() {
    _keepAliveTimer?.cancel();
    _keepAliveTimer = Timer.periodic(const Duration(seconds: 30), (_) async {
      if (_client == null || !_connected) return;
      try {
        await _enqueue(() => _client!.run('echo keepalive').timeout(const Duration(seconds: 10)));
      } catch (_) {
        // Автоматическое переподключение при потере связи.
        AppLogger.w('Keepalive lost, reconnecting to ${config.host}');
        _connected = false;
        try {
          _keepAliveTimer?.cancel();
          _keepAliveTimer = null;
          _client?.close();
          _client = null;
          await _connectInternal();
          _startKeepAlive();
        } catch (e) {
          AppLogger.e('Auto-reconnect failed', e);
        }
      }
    });
  }

  Future<void> reconnect() {
    return _enqueue(() async {
      _capabilities = null;
      _keepAliveTimer?.cancel();
      _keepAliveTimer = null;
      _client?.close();
      _client = null;
      _connected = false;
      await _connectInternal();
    });
  }

  Future<void> disconnect() {
    return _enqueue(() async {
      AppLogger.i('Disconnecting from ${config.host}');
      _keepAliveTimer?.cancel();
      _keepAliveTimer = null;
      _client?.close();
      _client = null;
      _connected = false;
    });
  }

  Future<String> runCommand(String command, {Duration timeout = const Duration(seconds: 30)}) {
    return _enqueue(() => _runCommand(command, timeout));
  }

  /// Команды, которым нужно больше времени (opkg update/install и т.п.),
  /// иначе стандартный таймаут 30 с обрывает установку пакетов.
  Future<String> runCommandLong(String command, {Duration timeout = const Duration(minutes: 5)}) {
    return _enqueue(() => _runCommand(command, timeout));
  }

  Future<String> _runCommand(String command, Duration timeout) async {
    if (_client == null || !_connected) {
      await _connectInternal();
    }
    try {
      final result = await _client!.run(command).timeout(timeout);
      _connected = true;
      return utf8.decode(result);
    } catch (e) {
      _connected = false;
      // Пробуем один раз переподключиться
      try {
        _keepAliveTimer?.cancel();
        _keepAliveTimer = null;
        _client?.close();
        _client = null;
        await _connectInternal();
        final result = await _client!.run(command).timeout(timeout);
        _connected = true;
        return utf8.decode(result);
      } catch (e2) {
        throw Exception('SSH ошибка: ${_readableError(e2)}');
      }
    }
  }

  /// Определяет версию и возможности OpenWrt (кэшируется).
  Future<OpenWrtCapabilities> detectCapabilities() async {
    if (_capabilities != null) return _capabilities!;
    try {
      final raw = await runCommand('cat /etc/openwrt_release 2>/dev/null || cat /etc/lsb-release 2>/dev/null');
      _capabilities = OpenWrtCapabilities.fromRelease(raw);
    } catch (_) {
      _capabilities = OpenWrtCapabilities();
    }
    return _capabilities!;
  }

  OpenWrtCapabilities? get capabilities => _capabilities;

  /// Возвращает правильную команду с учётом версии OpenWrt.
  Future<String> compatCmd(String operation) async {
    final caps = await detectCapabilities();
    switch (operation) {
      case 'wifi_scan':
        return caps.hasIwinfo ? 'iwinfo scan 2>/dev/null' : 'iw dev \$(iw dev 2>/dev/null | grep Interface | awk \'{print \$2}\') scan 2>/dev/null';
      case 'wifi_status':
        return caps.hasIwinfo ? 'iwinfo 2>/dev/null' : 'iw dev 2>/dev/null';
      case 'firewall_list':
        return caps.hasFirewall4 ? 'fw4 list 2>/dev/null' : 'fw3 list 2>/dev/null';
      case 'nft_rules':
        return caps.hasNftables ? 'nft list ruleset 2>/dev/null' : 'iptables-save 2>/dev/null';
      case 'switch_status':
        return caps.hasDsa ? 'ls /sys/class/net/ 2>/dev/null' : 'swconfig list 2>/dev/null';
      default:
        return operation;
    }
  }

  Future<SystemInfo> fetchSystemInfo() async {
    try {
      final raw = await runCommand('ubus call system info 2>/dev/null || echo "{}"');
      final json = jsonDecode(raw) as Map<String, dynamic>;
      if (json.isNotEmpty && json['hostname'] != null) {
        return SystemInfo.fromUbusJson(json);
      }
    } catch (_) {}

    // Fallback: читаем /proc напрямую
    try {
      final memRaw = await runCommand(r"awk '/MemTotal|MemAvailable|MemFree/{print $2}' /proc/meminfo 2>/dev/null || echo '0\n0\n0'");
final memLines = LineSplitter.split(memRaw).toList();
final memTotal = int.tryParse(memLines.isNotEmpty ? memLines[0] : '0') ?? 0;
final memAvail = int.tryParse(memLines.length > 1 ? memLines[1] : (memLines.length > 2 ? memLines[2] : '0')) ?? 0;
final loadRaw = await runCommand("cat /proc/loadavg 2>/dev/null || echo '0 0 0'");
final loadParts = loadRaw.trim().split(RegExp(r'\s+'));
final load1 = double.tryParse(loadParts.isNotEmpty ? loadParts[0] : '0') ?? 0;
final uptimeRaw = await runCommand(r"awk '{print $1}' /proc/uptime 2>/dev/null || echo '0'");
final uptime = int.tryParse(uptimeRaw.split('.').first) ?? 0;
String? model, firmware, kernel, hostname;
try {
final boardRaw = await runCommand('ubus call system board 2>/dev/null || echo "{}"');
final board = jsonDecode(boardRaw) as Map<String, dynamic>;
model = board['model']?.toString() ?? board['board_name']?.toString();
hostname = board['hostname']?.toString();
kernel = board['kernel']?.toString();
final release = board['release'] is Map ? board['release'] as Map<String, dynamic> : {};
firmware = '${release['distribution'] ?? 'OpenWrt'} ${release['version'] ?? ''}'.trim();
} catch (_) {}
return SystemInfo(
hostname: hostname ?? 'OpenWrt',
model: model ?? 'Unknown',
firmwareVersion: firmware ?? 'OpenWrt',
kernelVersion: kernel ?? '',
uptime: '${(uptime / 3600).toStringAsFixed(1)} ч.',
cpuLoad: load1,
memoryTotal: memTotal * 1024,
memoryFree: memAvail * 1024,
memoryUsed: (memTotal - memAvail) * 1024,
);
} catch (_) {}
return SystemInfo(
hostname: 'OpenWrt', model: 'Unknown', firmwareVersion: 'OpenWrt',
kernelVersion: '', uptime: '0 мин.', cpuLoad: 0, memoryTotal: 0, memoryFree: 0, memoryUsed: 0,
);
}
Future<Map<String, dynamic>> fetchBoardInfo() async {
final raw = await runCommand('ubus call system board');
return jsonDecode(raw) as Map<String, dynamic>;
}
Future<List> fetchWirelessDevices() async {
final raw = await runCommand('ubus call network.wireless status 2>/dev/null || echo "{}"');
final data = jsonDecode(raw) as Map<String, dynamic>;
final List devices = [];
for (final entry in data.entries) {
final name = entry.key;
final value = entry.value;
if (value is Map<String, dynamic>) {
String? htMode = value['config']?['htmode']?.toString();
if (htMode == null || htMode.isEmpty) {
try {
htMode = (await runCommand('uci get wireless.$name.htmode 2>/dev/null || echo ""')).trim();
if (htMode.isEmpty) htMode = null;
} catch (_) {}
}
devices.add(WifiDevice(
name: name,
up: value['up'] == true,
mac: value['config']?['macaddr']?.toString(),
channel: value['config']?['channel']?.toString(),
band: value['config']?['band']?.toString(),
txPower: int.tryParse(value['config']?['txpower']?.toString() ?? ''),
hwMode: value['config']?['hwmode']?.toString(),
htMode: htMode,
));
}
}
return devices;
}
Future<List> fetchWifiNetworks() async {
final raw = await runCommand('uci show wireless 2>/dev/null || echo ""');
final networks = [];
final sections = <String, Map<String, String>>{};
for (final line in LineSplitter.split(raw)) {
final idx = line.indexOf('=');
if (idx == -1) continue;
final key = line.substring(0, idx).trim();
final value = line.substring(idx + 1).trim().replaceAll("'", "").replaceAll('"', '');
final match = RegExp(r'^wireless.([^.]+).(ssid|device|disabled|encryption|mode|network)$').firstMatch(key);
if (match != null) {
final section = match.group(1)!;
final field = match.group(2)!;
sections.putIfAbsent(section, () => {});
sections[section]![field] = value;
}
}
final rawSections = await runCommand('uci show wireless 2>/dev/null | grep -E "^wireless\.[^=]+=wifi-iface" || echo ""');
final ifaceSections = {};
for (final line in LineSplitter.split(rawSections)) {
final match = RegExp(r'^wireless.([^=]+)=wifi-iface').firstMatch(line);
if (match != null) ifaceSections.add(match.group(1)!);
}
for (final section in ifaceSections) {
final fields = sections[section] ?? {};
if (fields.isEmpty) continue;
networks.add(WifiNetwork(
section: section,
ssid: fields['ssid'] ?? '',
device: fields['device'] ?? '',
disabled: fields['disabled'] == '1',
encryption: fields['encryption'],
mode: fields['mode'],
));
}
return networks;
}
Future toggleWifiNetwork(String section, bool enable) async {
await runCommand('uci set wireless.$section.disabled=${enable ? '0' : '1'}; uci commit wireless; wifi reload');
}
Future setWifiChannel(String device, String channel) async {
await runCommand('uci set wireless.$device.channel=$channel; uci commit wireless; wifi reload');
}
Future<Map<int, int>> scanWifiChannels(String device) async {
final raw = await runCommand('iwinfo $device scan 2>/dev/null || iw dev $device scan 2>/dev/null || echo ""');
final channels = <int, int>{};
final re = RegExp(r'Channel:\s*(\d+)|channel:\s*(\d+)', caseSensitive: false);
for (final m in re.allMatches(raw)) {
final ch = int.tryParse(m.group(1) ?? m.group(2) ?? '');
if (ch != null) {
channels[ch] = (channels[ch] ?? 0) + 1;
}
}
return channels;
}

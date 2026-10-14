/*  Copyright (C) 2026 Francesco Colasuonno

    This file is part of Gadgetbridge.

    Gadgetbridge is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Gadgetbridge is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>. */
package nodomain.freeyourgadget.gadgetbridge.service.devices.magic_touch

import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattService
import android.content.SharedPreferences
import android.widget.Toast
import nodomain.freeyourgadget.gadgetbridge.GBApplication
import nodomain.freeyourgadget.gadgetbridge.R
import nodomain.freeyourgadget.gadgetbridge.activities.devicesettings.DeviceSettingsPreferenceConst
import nodomain.freeyourgadget.gadgetbridge.devices.magic_touch.MagicTouchMiotSpec
import nodomain.freeyourgadget.gadgetbridge.impl.GBDevice
import nodomain.freeyourgadget.gadgetbridge.model.BatteryState
import nodomain.freeyourgadget.gadgetbridge.service.btle.AbstractBTLESingleDeviceSupport
import nodomain.freeyourgadget.gadgetbridge.service.btle.TransactionBuilder
import nodomain.freeyourgadget.gadgetbridge.service.devices.xiaomi_scooters.XiaomiScooterCrypto
import nodomain.freeyourgadget.gadgetbridge.util.CryptoUtils
import nodomain.freeyourgadget.gadgetbridge.util.GB
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.ArrayDeque
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Mijia Smart Neck and Shoulder Massager (xiaomi.magic_touch.jj02).
 *
 * Verified Xiaomi BLE StandardAuth (no ECDH, no scooter crypto):
 * - Login channel is UUID 0x0019 for BOTH directions (pre-key echo, SEND,
 *   randoms, confirms all go here as write-commands). UUID 0x0017 exists on
 *   the device but the vendor app never touches it.
 * - 6-byte transport frames: SEND `00 00 00 <op> 01 00` (op 0x0b/0x0a),
 *   RCV_RDY `00 00 01 01`, RCV_OK `00 00 01 00`, ACK `00 00 03 00`,
 *   OPEN_CMD `00 00 00 00 01 00`. (7-byte variants are silently ignored.)
 * - Session key: HKDF-SHA256(IKM = 12-byte cloud token,
 *   salt = appRandom || devRandom, info = "mible-login-info", L = 64);
 *   in-key [0:16] / out-key [16:32] / in-nonce [32:36] / out-nonce [36:40].
 * - Confirms: devConfirm = HMAC(in-key, devRandom||appRandom),
 *   appConfirm = HMAC(out-key, appRandom||devRandom).
 * - Data: AES-128-CCM, 12-byte nonce (prefix4 || 0000 || u16LE counter),
 *   4-byte tag, wire = u16LE(counter) || CT || tag.
 * - Operation on CMD 0x001a / REPORT 0x001b carries MiOT siid/piid payloads
 *   (see [MagicTouchMiotSpec]); PING `00 00 01 05 01 00` is answered with
 *   PONG `00 00 05 04 01 00`.
 *
 * Verified end-to-end against Mi Home HCI snoops (login, battery read,
 * power on/off, mode, heat on/off + level, timer) and a live Linux
 * login + encrypted command + decrypted telemetry round-trip.
 */
class MagicTouchJj02Support : AbstractBTLESingleDeviceSupport(LOG), SharedPreferences.OnSharedPreferenceChangeListener {
    private var authStep = AuthStep.IDLE
    private var appRandom: ByteArray? = null
    private var inKey: ByteArray? = null
    private var outKey: ByteArray? = null
    private var inPrefix: ByteArray? = null
    private var outPrefix: ByteArray? = null
    private var keyExchangeEchoes = 0
    private var appCmdCounter = 0
    private var miotMsgId = 0
    private val cmdQueue = ArrayDeque<ByteArray>()
    private var cmdBusy = false
    private var pendingCmd: ByteArray? = null
    private var pendingCounter = 0

    init {
        addSupportedService(UUID_SERVICE_XIAOMI)
    }

    override fun useAutoConnect(): Boolean = true

    override fun onServicesDiscovered(gatt: BluetoothGatt) {
        val sb = StringBuilder("GATT table:")
        for (service: BluetoothGattService in gatt.services) {
            sb.append("\n  service ").append(service.uuid)
            for (characteristic: BluetoothGattCharacteristic in service.characteristics) {
                // The vendor app only ever uses write-commands (0x52).
                if (service.uuid == UUID_SERVICE_XIAOMI) {
                    characteristic.writeType = BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE
                }
                sb.append("\n    char ").append(characteristic.uuid)
                    .append(" props=0x").append(Integer.toHexString(characteristic.properties))
            }
        }
        LOG.warn(sb.toString())
        super.onServicesDiscovered(gatt)
    }

    override fun initializeDevice(builder: TransactionBuilder): TransactionBuilder {
        authStep = AuthStep.IDLE
        appRandom = null
        lastDevRandom = null
        inKey = null
        outKey = null
        inPrefix = null
        outPrefix = null
        keyExchangeEchoes = 0
        appCmdCounter = 0
        miotMsgId = 0
        cmdQueue.clear()
        cmdBusy = false
        pendingCmd = null

        // Defensive: never stack listeners across reconnects/leaked supports.
        // The guard itself is static so even two live instances cannot ping-pong.
        activeInstance = this
        try {
            devicePrefs().unregisterOnSharedPreferenceChangeListener(this)
        } catch (e: Exception) {
            LOG.debug("Unregister prefs listener failed: {}", e.message)
        }
        devicePrefs().registerOnSharedPreferenceChangeListener(this)

        builder.setDeviceState(GBDevice.State.INITIALIZING)

        // Exact vendor-app order: subscribe report/cmd/info, version query,
        // subscribe the login channel, read firmware, MTU, then AUTH_START.
        // AUTH_CTRL notifications are enabled later, just before LOGIN_START.
        builder.notify(UUID_CHARACTERISTIC_REPORT, true)
        builder.notify(UUID_CHARACTERISTIC_COMMAND, true)
        builder.notify(UUID_CHARACTERISTIC_DEVICE_INFO, true)
        // 0x00 first (device answers 00 01 03, arming the channel), then 0x03.
        builder.write(UUID_CHARACTERISTIC_DEVICE_INFO, 0x00.toByte())
        builder.write(UUID_CHARACTERISTIC_DEVICE_INFO, 0x03.toByte())
        builder.notify(UUID_CHARACTERISTIC_LOGIN, true)
        builder.read(UUID_CHARACTERISTIC_FIRMWARE_VERSION)
        builder.requestMtu(247)

        if (getToken() == null) {
            // Add-first-key-later: stay connected with the unencrypted channels
            // so the card works; login starts as soon as the token is saved.
            LOG.warn("No cloud token configured, skipping login (set it in device settings)")
            gbDevice.setUpdateState(GBDevice.State.INITIALIZED, context)
            GB.toast(context, R.string.magic_touch_jj02_bind_key_summary, Toast.LENGTH_LONG, GB.WARN)
            return builder
        }

        builder.write(UUID_CHARACTERISTIC_AUTH_CTRL, *AUTH_START)
        authStep = AuthStep.EXPECT_KEY_EXCHANGE

        // Initialization finishes asynchronously on LOGIN_OK -- see onLoginOk().
        return builder
    }

    override fun dispose() {
        try {
            devicePrefs().unregisterOnSharedPreferenceChangeListener(this)
        } catch (e: Exception) {
            LOG.debug("Unregister prefs listener failed: {}", e.message)
        }
        if (activeInstance === this) {
            activeInstance = null
        }
        super.dispose()
    }

    /**
     * Single entry for UI commands (card icons via ConfigurationAction,
     * dashboard widgets). Values encode in the key; toggles/cycles read
     * last-known state. All sends go through the gated setX helpers.
     */
    override fun onSendConfiguration(config: String) {
        LOG.warn("onSendConfiguration: {}", config)
        if (activeInstance !== this) {
            LOG.warn("Ignoring config from stale instance")
            return
        }
        if (authStep != AuthStep.DONE && config != "refresh") {
            notReady()
            return
        }
        val prefs = devicePrefs()
        when (config) {
            "power_toggle" -> setPower(!prefs.getBoolean(PREF_POWER, false))
            "mode_next" -> {
                val cur = prefs.getString(PREF_MODE, "1")?.toIntOrNull() ?: 1
                setMode(if (cur >= 4) 1 else cur + 1)
            }
            "mode_1", "mode_2", "mode_3", "mode_4" ->
                setMode(config.substringAfter("mode_").toInt())
            "heat_toggle" -> setHeating(!prefs.getBoolean(PREF_HEATING, false))
            "heat_on" -> setHeating(true)
            "heat_off" -> setHeating(false)
            "level_next" -> {
                val cur = prefs.getString(PREF_HEAT_LEVEL, "1")
                setHeatLevel(if (cur == "1") 2 else 1)
            }
            "level_1" -> setHeatLevel(1)
            "level_2" -> setHeatLevel(2)
            "timer_next" -> {
                val presets = listOf(5, 10, 15, 20)
                val cur = prefs.getString(PREF_TIMER, "15")?.toIntOrNull() ?: 15
                setTimerMinutes(presets.firstOrNull { it > cur } ?: presets.first())
            }
            "timer_5" -> setTimerMinutes(5)
            "timer_10" -> setTimerMinutes(10)
            "timer_15" -> setTimerMinutes(15)
            "timer_20" -> setTimerMinutes(20)
            "refresh" -> refreshAll()
            else -> LOG.warn("Unknown configuration key: {}", config)
        }
    }

    /** Kick off the login on an already-connected device (token was set later). */
    private fun startLogin() {
        authStep = AuthStep.EXPECT_KEY_EXCHANGE
        keyExchangeEchoes = 0
        createTransactionBuilder("magic_touch_start_login")
            .write(UUID_CHARACTERISTIC_AUTH_CTRL, *AUTH_START)
            .queue()
    }

    private fun devicePrefs(): SharedPreferences {
        return GBApplication.getDeviceSpecificSharedPrefs(gbDevice.address)
    }

    override fun onCharacteristicChanged(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
        value: ByteArray,
    ): Boolean {
        when (characteristic.uuid) {
            UUID_CHARACTERISTIC_AUTH_CTRL -> {
                handleAuthCtrl(value)
                return true
            }
            UUID_CHARACTERISTIC_LOGIN -> {
                handleLoginChannel(value)
                return true
            }
            UUID_CHARACTERISTIC_COMMAND -> {
                handleCommandChannel(value)
                return true
            }
            UUID_CHARACTERISTIC_REPORT -> {
                handleReport(value)
                return true
            }
            else -> {
                LOG.warn("NOTIFY {} len={}: {}", characteristic.uuid, value.size, GB.hexdump(value))
                return true
            }
        }
    }

    // =======================================================================
    // Login handshake (Xiaomi BLE StandardAuth, verified)
    // =======================================================================

    private fun handleAuthCtrl(value: ByteArray) {
        when {
            value.contentEquals(LOGIN_OK) -> onLoginOk()
            value.contentEquals(LOGIN_FAIL) -> authFailed("device rejected login (LOGIN_FAIL)")
            else -> LOG.warn("Unexpected AUTH_CTRL frame in step {}: {}", authStep, GB.hexdump(value))
        }
    }

    private fun handleLoginChannel(value: ByteArray) {
        when {
            // Pre-key exchange: echo back with type 04 -> 05 on the SAME channel.
            startsWith(value, 0x00, 0x00, 0x04) -> {
                if (authStep != AuthStep.EXPECT_KEY_EXCHANGE) {
                    LOG.warn("Unexpected key-exchange PDU in step {}", authStep)
                    return
                }
                val echo = byteArrayOf(0x00.toByte(), 0x00.toByte(), 0x05.toByte()) + value.copyOfRange(3, value.size)
                write(UUID_CHARACTERISTIC_LOGIN, echo)
                keyExchangeEchoes++
                // The second PDU (index byte 0x01, 244 bytes total) completes it.
                if ((value.size > 3 && value[3] == 0x01.toByte()) || keyExchangeEchoes >= 2) {
                    beginLogin()
                }
            }
            value.contentEquals(RCV_RDY) -> when (authStep) {
                AuthStep.EXPECT_SEND_RDY -> sendAppRandom()
                AuthStep.EXPECT_CONFIRM_RDY -> sendAppConfirm()
                else -> LOG.warn("Unexpected RCV_RDY in auth step {}", authStep)
            }
            value.contentEquals(RCV_OK) -> {
                if (authStep == AuthStep.EXPECT_CONFIRM_OK) {
                    authStep = AuthStep.EXPECT_LOGIN_OK
                }
                LOG.debug("RCV_OK in step {}", authStep)
            }
            startsWith(value, 0x00, 0x00, 0x02, 0x0d) -> onDeviceRandom(value)
            startsWith(value, 0x00, 0x00, 0x02, 0x0c) -> onDeviceConfirm(value)
            value.contentEquals(PING) -> {
                // Device keepalive: answer or it stops talking on long sessions.
                write(UUID_CHARACTERISTIC_LOGIN, PONG)
            }
            else -> LOG.warn("Unhandled login-channel frame in step {}: {}", authStep, GB.hexdump(value))
        }
    }

    /**
     * Vendor order: AUTH_CTRL notifications only now, then LOGIN_START and
     * SEND back-to-back in one transaction (order + pacing matter).
     */
    private fun beginLogin() {
        authStep = AuthStep.EXPECT_SEND_RDY
        createTransactionBuilder("magic_touch_begin_login")
            .notify(UUID_CHARACTERISTIC_AUTH_CTRL, true)
            .sleep(50)
            .write(UUID_CHARACTERISTIC_AUTH_CTRL, *LOGIN_START)
            .sleep(15)
            .write(UUID_CHARACTERISTIC_LOGIN, *SEND_KEY)
            .queue()
    }

    private fun sendAppRandom() {
        val random = ByteArray(16)
        SecureRandom().nextBytes(random)
        appRandom = random
        // Never log the random itself.
        write(UUID_CHARACTERISTIC_LOGIN, PREFIX_DATA + random)
        authStep = AuthStep.EXPECT_DEVICE_RANDOM
    }

    private fun onDeviceRandom(value: ByteArray) {
        if (value.size != 20) {
            LOG.warn("Bad devRandom length {}", value.size)
            return
        }
        val appR = appRandom
        if (appR == null) {
            LOG.warn("devRandom before appRandom, ignoring")
            return
        }
        val devR = value.copyOfRange(4, 20)
        lastDevRandom = devR
        write(UUID_CHARACTERISTIC_LOGIN, ACK)
        val token = getToken()
        if (token == null) {
            authFailed("no 12-byte cloud token configured, cannot derive session key")
            return
        }
        try {
            val okm = CryptoUtils.hkdfSha256(
                token,
                appR + devR,
                HKDF_INFO.toByteArray(Charsets.US_ASCII),
                64,
            )
            inKey = okm.copyOfRange(0, 16)
            outKey = okm.copyOfRange(16, 32)
            inPrefix = okm.copyOfRange(32, 36)
            outPrefix = okm.copyOfRange(36, 40)
        } catch (e: Exception) {
            authFailed("session key derivation failed: ${e.message}")
            return
        }
        authStep = AuthStep.EXPECT_DEVICE_CONFIRM
    }

    private fun onDeviceConfirm(value: ByteArray) {
        if (value.size != 36) {
            LOG.warn("Bad devConfirm length {}", value.size)
            return
        }
        val inK = inKey
        val outK = outKey
        val appR = appRandom
        if (inK == null || outK == null || appR == null) {
            LOG.warn("devConfirm with no session, ignoring")
            return
        }
        val devR = lastDevRandom
        if (devR == null) {
            LOG.warn("devConfirm with no devRandom, ignoring")
            return
        }
        val expected = hmacSha256(inK, devR + appR)
        if (expected == null || !MessageDigest.isEqual(expected, value.copyOfRange(4, 36))) {
            authFailed("device confirm MAC mismatch (wrong token?)")
            return
        }
        LOG.warn("Device confirm verified")
        write(UUID_CHARACTERISTIC_LOGIN, ACK)
        write(UUID_CHARACTERISTIC_LOGIN, SEND_INFO)
        authStep = AuthStep.EXPECT_CONFIRM_RDY
    }

    private var lastDevRandom: ByteArray? = null

    private fun sendAppConfirm() {
        val outK = outKey
        val appR = appRandom
        val devR = lastDevRandom
        if (outK == null || appR == null || devR == null) {
            authFailed("cannot build app confirm (no session)")
            return
        }
        val confirm = hmacSha256(outK, appR + devR)
        if (confirm == null) {
            authFailed("cannot build app confirm")
            return
        }
        write(UUID_CHARACTERISTIC_LOGIN, PREFIX_DATA + confirm)
        authStep = AuthStep.EXPECT_CONFIRM_OK
    }

    private fun onLoginOk() {
        LOG.warn("Login successful, session established")
        authStep = AuthStep.DONE
        gbDevice.setUpdateState(GBDevice.State.INITIALIZED, context)
        // Dashboard shows last-known % immediately (level pushes are rare).
        // One-time migration: parse the old display string if the int key
        // was never saved (e.g. "40% · Charging" stored by previous builds).
        try {
            var pct = savedBatteryPct()
            if (pct == null) {
                val last = devicePrefs().getString(PREF_BATTERY, "")
                val m = Regex("(\\d+)%").find(last ?: "")
                pct = m?.groupValues?.get(1)?.toIntOrNull()
                if (pct != null && pct in 0..100) {
                    saveBatteryPct(pct)
                }
            }
            if (pct != null && pct in 0..100) {
                lastBatteryPct = pct
                updateBatteryDisplay()
                try {
                    gbDevice.sendDeviceUpdateIntent(context)
                } catch (e: Exception) {
                    LOG.debug("sendDeviceUpdateIntent failed: {}", e.message)
                }
            }
        } catch (e: Exception) {
            LOG.debug("Restore battery failed: {}", e.message)
        }
        // Read-only refresh so live state shows up immediately (battery, then
        // full property set -- the vendor app does the same on every connect).
        sendMiotCommand(BATTERY_CAP)
        sendMiotCommand(buildBulkGet())
    }

    private fun authFailed(reason: String) {
        LOG.error("Authentication failed: {}", reason)
        authStep = AuthStep.IDLE
        GB.toast(context, R.string.authentication_failed_check_key, Toast.LENGTH_LONG, GB.WARN)
        GBApplication.deviceService(device)?.disconnect()
    }

    // =======================================================================
    // Encrypted operation channel (CMD 0x001a / REPORT 0x001b)
    // =======================================================================

    /**
     * Queue a plaintext MiOT command for sending. Commands go out one at a
     * time (OPEN -> RCV_RDY -> frame -> RCV_OK), exactly like the vendor app.
     */
    fun sendMiotCommand(plaintext: ByteArray) {
        if (activeInstance !== this) {
            return
        }
        cmdQueue.addLast(plaintext)
        pumpCommandQueue()
    }

    private var lastPower: Int? = null

    /** On charger (battery status 2, or power state 2): the device refuses
     * all control writes. Refreshed on every bulk read via power. */
    private fun isCharging(): Boolean = lastBatteryStatus == 2 || lastPower == 2

    private fun isPoweredOn(): Boolean {
        return try {
            devicePrefs().getBoolean(PREF_POWER, false)
        } catch (e: Exception) {
            false
        }
    }

    private fun requirePoweredOn(): Boolean {
        if (!isPoweredOn()) {
            GB.toast(context, R.string.magic_touch_turn_on_first, Toast.LENGTH_LONG, GB.WARN)
            return false
        }
        return true
    }

    private fun requireNotCharging(): Boolean {
        if (isCharging()) {
            GB.toast(context, R.string.magic_touch_unplug_charger, Toast.LENGTH_LONG, GB.WARN)
            return false
        }
        return true
    }

    fun setPower(on: Boolean) {
        if (!requireNotCharging()) return
        sendMiotCommand(buildSet(MagicTouchMiotSpec.PID_ON, TYPE_UINT8, if (on) 1 else 0))
    }

    fun setMode(mode: Int) {
        require(mode in 1..4) { "mode must be 1..4" }
        if (!requireNotCharging() || !requirePoweredOn()) return
        sendMiotCommand(buildSet(MagicTouchMiotSpec.PID_MODE, TYPE_UINT8, mode))
    }

    fun setHeating(on: Boolean) {
        // Heating uses type byte 0x00 (verified captures), unlike the 0x10 elsewhere.
        if (!requireNotCharging() || !requirePoweredOn()) return
        sendMiotCommand(buildSet(MagicTouchMiotSpec.PID_HEATING, 0x00, if (on) 1 else 0))
    }

    fun setHeatLevel(level: Int) {
        require(level in 1..2) { "heat level must be 1 (40C) or 2 (45C)" }
        if (!requireNotCharging() || !requirePoweredOn()) return
        sendMiotCommand(buildSet(MagicTouchMiotSpec.PID_HEAT_LEVEL, TYPE_UINT8, level))
    }

    fun setTimerMinutes(minutes: Int) {
        require(minutes in 2..20) { "timer must be 2..20 minutes" }
        if (!requireNotCharging() || !requirePoweredOn()) return
        sendMiotCommand(buildSet(MagicTouchMiotSpec.PID_TARGET_TIME, TYPE_UINT8, minutes))
    }

    fun refreshAll() {
        sendMiotCommand(BATTERY_CAP)
        sendMiotCommand(buildBulkGet())
    }

    private fun pumpCommandQueue() {
        if (cmdBusy || cmdQueue.isEmpty() || authStep != AuthStep.DONE) {
            return
        }
        cmdBusy = true
        pendingCmd = cmdQueue.removeFirst()
        pendingCounter = appCmdCounter
        write(UUID_CHARACTERISTIC_COMMAND, OPEN_CMD)
    }

    private fun handleCommandChannel(value: ByteArray) {
        when {
            value.contentEquals(RCV_RDY) -> {
                val plain = pendingCmd
                val outK = outKey
                val outP = outPrefix
                if (!cmdBusy || plain == null || outK == null || outP == null) {
                    LOG.warn("Unexpected CMD RCV_RDY (no pending command)")
                    return
                }
                val counterBytes = u16le(pendingCounter)
                val ct = XiaomiScooterCrypto.encryptCcm(
                    outK,
                    XiaomiScooterCrypto.buildNonce(outP, pendingCounter),
                    plain,
                )
                write(UUID_CHARACTERISTIC_COMMAND, PREFIX_DATA + counterBytes + ct)
                appCmdCounter = (pendingCounter + 1) and 0xffff
            }
            value.contentEquals(RCV_OK) -> {
                pendingCmd = null
                cmdBusy = false
                pumpCommandQueue()
            }
            else -> LOG.warn("Unexpected CMD frame: {}", GB.hexdump(value))
        }
    }

    private fun handleReport(value: ByteArray) {
        if (!startsWith(value, 0x00, 0x00, 0x02, 0x00) || value.size < 7) {
            LOG.warn("Unexpected REPORT frame: {}", GB.hexdump(value))
            return
        }
        write(UUID_CHARACTERISTIC_REPORT, ACK)
        if (authStep != AuthStep.DONE) {
            return
        }
        val inK = inKey
        val inP = inPrefix
        if (inK == null || inP == null) {
            LOG.warn("Encrypted report with no session")
            return
        }
        val counter = u16leOf(value, 4)
        try {
            val pt = XiaomiScooterCrypto.decryptCcm(
                inK,
                XiaomiScooterCrypto.buildNonce(inP, counter),
                value.copyOfRange(6, value.size),
            )
            LOG.warn("REPORT ctr={} {}", counter, decodeMiotReport(pt))
            syncPrefsFromTelemetry(pt)
            try {
                gbDevice.sendDeviceUpdateIntent(context)
            } catch (e: Exception) {
                LOG.debug("sendDeviceUpdateIntent failed: {}", e.message)
            }
        } catch (e: Exception) {
            LOG.warn("Failed to decrypt report ctr={}: {}", counter, e.message)
        }
    }

    // =======================================================================
    // MiOT payload builders / decoder (siid 4 control; see MagicTouchMiotSpec)
    // =======================================================================

    /**
     * Set-property template (verified): `0c 20 <msgId LE> 00 01 04 <piid>
     * 00 01 <type> <value>` -- 12 bytes, value in the last byte.
     */
    private fun buildSet(piid: Int, typeByte: Int, value: Int): ByteArray {
        val msgId = miotMsgId++ and 0xffff
        return byteArrayOf(
            0x0c.toByte(), 0x20.toByte(),
            (msgId and 0xff).toByte(), ((msgId shr 8) and 0xff).toByte(),
            0x00.toByte(), 0x01.toByte(), 0x04.toByte(),
            piid.toByte(), 0x00.toByte(), 0x01.toByte(),
            typeByte.toByte(), value.toByte(),
        )
    }

    private fun buildBulkGet(): ByteArray {
        // Exact vendor property list (siid 4 piids 1,2,3,4,5,6,8,10,11,12).
        val msgId = miotMsgId++ and 0xffff
        return byteArrayOf(
            0x27.toByte(), 0x20.toByte(),
            (msgId and 0xff).toByte(), ((msgId shr 8) and 0xff).toByte(),
            0x02.toByte(), 0x0b.toByte(), 0x05.toByte(), 0xeb.toByte(), 0x03.toByte(),
            0x04.toByte(), 0x0a.toByte(), 0x00.toByte(),
            0x04.toByte(), 0x01.toByte(), 0x00.toByte(),
            0x04.toByte(), 0x02.toByte(), 0x00.toByte(),
            0x04.toByte(), 0x03.toByte(), 0x00.toByte(),
            0x04.toByte(), 0x04.toByte(), 0x00.toByte(),
            0x04.toByte(), 0x05.toByte(), 0x00.toByte(),
            0x04.toByte(), 0x06.toByte(), 0x00.toByte(),
            0x04.toByte(), 0x08.toByte(), 0x00.toByte(),
            0x04.toByte(), 0x0b.toByte(), 0x00.toByte(),
            0x04.toByte(), 0x0c.toByte(), 0x00.toByte(),
        )
    }

    /** Short single-property frame: 12B/11B `LL 20 MM MM .. siid piid .. val`.
     * 12B layout matches our verified SET bytes: siid=[6], piid=[7], val=[11];
     * 11B acks: siid=[6], piid=[7], val=[10]. siid-5 battery level uses a
     * 2-byte LE piid (`05 EB 03` = 1003). Null if not a short frame. */
    private fun parseShort(pt: ByteArray): Triple<Int, Int, Int>? {
        if (pt.size < 4 || pt[1] != 0x20.toByte()) return null
        if (pt.size == 12 && (pt[6].toInt() and 0xff) == 5
            && (pt[7].toInt() and 0xff) == 0xeb && (pt[8].toInt() and 0xff) == 0x03
        ) {
            return Triple(5, 1003, pt[11].toInt() and 0xff)
        }
        return when (pt.size) {
            12 -> Triple(pt[6].toInt() and 0xff, pt[7].toInt() and 0xff, pt[11].toInt() and 0xff)
            11 -> Triple(pt[6].toInt() and 0xff, pt[7].toInt() and 0xff, pt[10].toInt() and 0xff)
            else -> null
        }
    }

    /** Best-effort human-readable rendering of a decrypted MiOT report. */
    private fun decodeMiotReport(pt: ByteArray): String {
        if (pt.size < 4 || pt[1] != 0x20.toByte()) {
            return GB.hexdump(pt)
        }
        val msgId = u16leOf(pt, 2)
        val a0 = pt.indexOf(0xa0.toByte())
        if (a0 >= 0 && a0 + 1 < pt.size) {
            val str = try {
                String(pt.copyOfRange(a0 + 1, pt.size), Charsets.US_ASCII)
            } catch (e: Exception) {
                "?"
            }
            return "msg=$msgId str=$str ${GB.hexdump(pt)}"
        }
        val short = parseShort(pt) ?: return "msg=$msgId ${GB.hexdump(pt)}"
        val (siid, piid, valByte) = short
        if (siid == 5 && piid == 2) {
            return "msg=$msgId battery-status=$valByte ${GB.hexdump(pt)}"
        }
        if (siid == 5 && piid == 1003) {
            val pct = if (valByte in 0..20) valByte * 5 else valByte
            return "msg=$msgId battery-level=$pct% (raw=$valByte) ${GB.hexdump(pt)}"
        }
        if (siid != 4) {
            return "msg=$msgId siid=$siid piid=$piid val=$valByte ${GB.hexdump(pt)}"
        }
        val ok = isValidValue(piid, valByte)
        return "msg=$msgId ${propName(piid)}=$valByte${if (ok) "" else " (INVALID)"} ${GB.hexdump(pt)}"
    }

    private fun propName(piid: Int): String = when (piid) {
        MagicTouchMiotSpec.PID_MODE -> "mode(1=Gentle,2=Relax,3=Stress,4=Custom)"
        MagicTouchMiotSpec.PID_DEFAULT_MODE -> "default-mode"
        MagicTouchMiotSpec.PID_TARGET_TIME -> "timer-min"
        MagicTouchMiotSpec.PID_COUNTDOWN -> "countdown-min"
        MagicTouchMiotSpec.PID_HEATING -> "heating"
        MagicTouchMiotSpec.PID_HEAT_LEVEL -> "heat-level(1=40C,2=45C)"
        MagicTouchMiotSpec.PID_DEFAULT_HEAT_MODE -> "default-heat-mode"
        MagicTouchMiotSpec.PID_DEFAULT_BEEP_MODE -> "beep"
        MagicTouchMiotSpec.PID_MASSAGE_MANIPULATION -> "manipulation"
        MagicTouchMiotSpec.PID_ON -> "power(0=off,1=on)"
        MagicTouchMiotSpec.PID_CUSTOM_NAME -> "name"
        MagicTouchMiotSpec.PID_MASSAGE_HEAD_INIT -> "head-init"
        else -> "piid=$piid"
    }

    // =======================================================================
    // Device settings card (add-first-key-later + two-way sync)
    // =======================================================================

    override fun onSharedPreferenceChanged(prefs: SharedPreferences, key: String?) {
        if (syncingPrefs) {
            return
        }
        if (activeInstance !== this) {
            // Stale support (leaked across reconnect/update): never send.
            return
        }
        // Commands come from the control card via broadcasts, never from prefs.
        // The command/battery prefs below are a state store written from
        // telemetry for the card to display; user edits must not send.
        if (key == DeviceSettingsPreferenceConst.PREF_AUTH_KEY || key == PREF_MAGIC_TOUCH_BIND_KEY) {
            if (isConnected() && authStep == AuthStep.IDLE) {
                LOG.warn("Token saved, starting login")
                startLogin()
            }
        }
    }

    private fun notReady() {
        GB.toast(context, R.string.device_not_connected, Toast.LENGTH_LONG, GB.WARN)
    }

    private fun setPrefBoolean(key: String, v: Boolean) {
        syncingPrefs = true
        try {
            devicePrefs().edit().putBoolean(key, v).apply()
        } finally {
            syncingPrefs = false
        }
    }

    private fun setPrefString(key: String, v: String) {
        syncingPrefs = true
        try {
            devicePrefs().edit().putString(key, v).apply()
        } finally {
            syncingPrefs = false
        }
    }

    /** Mirror device truth into the settings card (guarded, never loops back).
     * Out-of-range values are ignored, never written (a malformed decode must
     * not flip the card and re-trigger a command). */
    private fun syncPrefsFromTelemetry(pt: ByteArray) {
        if (pt.size < 4 || pt[1] != 0x20.toByte()) {
            return
        }
        if (pt.size > 20) {
            syncBulk(pt)
            return
        }
        val short = parseShort(pt) ?: return
        val (siid, piid, valByte) = short
        if (siid == 5 && piid == 2) {
            if (valByte in 0..2) {
                lastBatteryStatus = valByte
                updateBatteryDisplay()
            }
            return
        }
        if (siid == 5 && piid == 1003) {
            // Device sends 0..20 steps; displayed % is raw*5 (verified: 6->30,
            // 7->35, 8->40). Fall back to direct % if ever > 20.
            val pct = if (valByte in 0..20) valByte * 5 else valByte
            if (pct in 0..100) {
                lastBatteryPct = pct
                saveBatteryPct(pct)
                updateBatteryDisplay()
            }
            return
        }
        if (siid != 4 || !isValidValue(piid, valByte)) {
            return
        }
        syncProperty(piid, valByte)
    }

    private fun isValidValue(piid: Int, v: Int): Boolean = when (piid) {
        MagicTouchMiotSpec.PID_ON -> v in 0..3
        MagicTouchMiotSpec.PID_MODE -> v in 1..4
        MagicTouchMiotSpec.PID_HEATING -> v in 0..1
        MagicTouchMiotSpec.PID_HEAT_LEVEL -> v in 1..2
        MagicTouchMiotSpec.PID_TARGET_TIME -> v in 2..20
        MagicTouchMiotSpec.PID_COUNTDOWN -> v in 2..20
        else -> false
    }

    private fun batteryStatusText(v: Int): String = when (v) {
        0 -> "Off"
        1 -> "On"
        2 -> "Charging"
        else -> "Unknown"
    }

    private var lastBatteryPct: Int? = null
    private var lastBatteryStatus: Int? = null

    /** Combined "40% · Charging" display + dashboard level/state. The numeric
     * level lives in its own persisted key so status-only updates can never
     * wipe it (that blanked the dashboard after every restart). */
    private fun updateBatteryDisplay() {
        val pct = lastBatteryPct ?: savedBatteryPct()
        val st = lastBatteryStatus
        val text = when {
            pct != null && st != null -> "$pct% · ${batteryStatusText(st)}"
            pct != null -> "$pct%"
            st != null -> batteryStatusText(st)
            else -> return
        }
        setPrefString(PREF_BATTERY, text)
        if (pct != null) {
            try {
                gbDevice.setBatteryLevel(pct, 0)
            } catch (e: Exception) {
                LOG.debug("setBatteryLevel failed: {}", e.message)
            }
        }
        try {
            val state = when (st) {
                2 -> BatteryState.BATTERY_CHARGING
                1, 0 -> BatteryState.BATTERY_NORMAL
                else -> BatteryState.UNKNOWN
            }
            gbDevice.setBatteryState(state, 0)
        } catch (e: Exception) {
            LOG.debug("setBatteryState failed: {}", e.message)
        }
        // Dashboard/widgets refresh via handleReport's update intent (or the
        // login restore below), not here, to avoid double refreshes.
    }

    private fun savedBatteryPct(): Int? {
        return try {
            val v = devicePrefs().getInt(PREF_BATTERY_LEVEL, -1)
            if (v in 0..100) v else null
        } catch (e: Exception) {
            null
        }
    }

    private fun saveBatteryPct(pct: Int) {
        syncingPrefs = true
        try {
            devicePrefs().edit().putInt(PREF_BATTERY_LEVEL, pct).apply()
        } finally {
            syncingPrefs = false
        }
    }

    /** Bulk get-properties response: `04 <piid> 00` markers, 8-byte numeric
     * entries (value = last byte), string entry for piid 11. */
    private fun syncBulk(pt: ByteArray) {
        var i = 0
        while (i + 2 < pt.size) {
            if (pt[i] == 0x04.toByte() && pt[i + 2] == 0x00.toByte()) {
                val piid = pt[i + 1].toInt() and 0xff
                if (piid == MagicTouchMiotSpec.PID_CUSTOM_NAME) {
                    // `04 0b 00 00 00 <len> a0 <str>`: just log the name.
                    if (i + 6 < pt.size && pt[i + 6] == 0xa0.toByte()) {
                        val len = pt[i + 5].toInt() and 0xff
                        val end = (i + 7 + len).coerceAtMost(pt.size)
                        val name = try {
                            String(pt.copyOfRange(i + 7, end), Charsets.US_ASCII)
                        } catch (e: Exception) {
                            "?"
                        }
                        LOG.warn("Device name: {}", name)
                    }
                } else if (piid in 1..12 && i + 7 < pt.size) {
                    syncProperty(piid, pt[i + 7].toInt() and 0xff)
                }
            }
            i++
        }
    }

    private fun syncProperty(piid: Int, v: Int) {
        if (!isValidValue(piid, v)) {
            LOG.warn("Ignoring out-of-range piid={} val={}", piid, v)
            return
        }
        // Power=2 means on charger: refresh the charging interlock on every
        // bulk read, since siid-5 status only pushes on plug/unplug events.
        // Power 0/1 proves disconnected, so a stuck charging flag is cleared.
        if (piid == MagicTouchMiotSpec.PID_ON) {
            lastPower = v
            if (v == 2 && lastBatteryStatus != 2) {
                lastBatteryStatus = 2
                updateBatteryDisplay()
            } else if ((v == 0 || v == 1) && lastBatteryStatus == 2) {
                lastBatteryStatus = null
                updateBatteryDisplay()
            }
        }
        when (piid) {
            MagicTouchMiotSpec.PID_ON -> setPrefBoolean(PREF_POWER, v == 1)
            MagicTouchMiotSpec.PID_MODE -> setPrefString(PREF_MODE, v.toString())
            MagicTouchMiotSpec.PID_HEATING -> setPrefBoolean(PREF_HEATING, v == 1)
            MagicTouchMiotSpec.PID_HEAT_LEVEL -> setPrefString(PREF_HEAT_LEVEL, v.toString())
            MagicTouchMiotSpec.PID_TARGET_TIME -> setPrefString(PREF_TIMER, v.toString())
            // Countdown, defaults, head-init are display-only/logged.
        }
    }

    // =======================================================================
    // Helpers
    // =======================================================================

    private fun write(characteristic: UUID, data: ByteArray) {
        createTransactionBuilder("magic_touch_write_$characteristic")
            .write(characteristic, *data)
            .sleep(30)
            .queue()
    }

    /**
     * 12-byte cloud token (24 hex chars). This is the Mi Home "token", NOT the
     * 16-byte BLE bind key -- only the token derives the session key.
     * Standard `authkey` slot first (AuthKeyActivity + settings), legacy
     * device-specific slot as fallback so saved tokens keep working.
     */
    private fun getToken(): ByteArray? {
        val prefs = GBApplication.getDeviceSpecificSharedPrefs(gbDevice.address)
        val std = prefs?.getString(DeviceSettingsPreferenceConst.PREF_AUTH_KEY, "")?.trim() ?: ""
        val legacy = prefs?.getString(PREF_MAGIC_TOUCH_BIND_KEY, "")?.trim() ?: ""
        for (raw in listOf(std, legacy)) {
            if (raw.isEmpty()) continue
            val hex = if (raw.startsWith("0x")) raw.substring(2) else raw
            if (hex.length != 24) continue
            val bytes = runCatching { GB.hexStringToByteArray(hex) }.getOrNull()
            if (bytes != null && bytes.size == 12) return bytes
        }
        LOG.error("No 12-byte cloud token configured (authkey or legacy slot)")
        return null
    }

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray? {
        return try {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(key, "HmacSHA256"))
            mac.doFinal(data)
        } catch (e: Exception) {
            LOG.error("HMAC-SHA256 failed: {}", e.message)
            null
        }
    }

    private fun startsWith(v: ByteArray, vararg p: Int): Boolean {
        if (v.size < p.size) return false
        for (i in p.indices) {
            if ((v[i].toInt() and 0xff) != p[i]) return false
        }
        return true
    }

    private fun u16le(v: Int): ByteArray {
        return ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN).putShort(v.toShort()).array()
    }

    private fun u16leOf(v: ByteArray, off: Int): Int {
        return (v[off].toInt() and 0xff) or ((v[off + 1].toInt() and 0xff) shl 8)
    }

    private enum class AuthStep {
        IDLE,
        EXPECT_KEY_EXCHANGE,
        EXPECT_SEND_RDY,
        EXPECT_DEVICE_RANDOM,
        EXPECT_DEVICE_CONFIRM,
        EXPECT_CONFIRM_RDY,
        EXPECT_CONFIRM_OK,
        EXPECT_LOGIN_OK,
        DONE,
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(MagicTouchJj02Support::class.java)

        /**
         * Static re-entrancy guard: telemetry syncs must never re-trigger sends,
         * even if two support instances (e.g. across a reconnect) are alive.
         * A per-instance flag allowed ping-pong ON/OFF loops.
         */
        private var syncingPrefs = false

        /** Only the most recently initialized instance may send; stale ones stay silent. */
        private var activeInstance: MagicTouchJj02Support? = null

        val UUID_SERVICE_XIAOMI: UUID = UUID.fromString("0000fe95-0000-1000-8000-00805f9b34fb")
        val UUID_CHARACTERISTIC_AUTH_CTRL: UUID = UUID.fromString("00000010-0000-1000-8000-00805f9b34fb")

        /**
         * Login channel, BOTH directions (echo, SEND, randoms, confirms).
         * The vendor app never uses UUID 0x0017; it only listens on 0x0019.
         */
        val UUID_CHARACTERISTIC_LOGIN: UUID = UUID.fromString("00000019-0000-1000-8000-00805f9b34fb")
        val UUID_CHARACTERISTIC_COMMAND: UUID = UUID.fromString("0000001a-0000-1000-8000-00805f9b34fb")
        val UUID_CHARACTERISTIC_REPORT: UUID = UUID.fromString("0000001b-0000-1000-8000-00805f9b34fb")
        val UUID_CHARACTERISTIC_DEVICE_INFO: UUID = UUID.fromString("0000001c-0000-1000-8000-00805f9b34fb")

        /** Firmware version string ("2.1.2"), read-only. */
        val UUID_CHARACTERISTIC_FIRMWARE_VERSION: UUID = UUID.fromString("00000004-0000-1000-8000-00805f9b34fb")

        const val PREF_MAGIC_TOUCH_BIND_KEY = "pref_magic_touch_jj02_bind_key"
        const val PREF_POWER = "pref_magic_touch_jj02_power"
        const val PREF_MODE = "pref_magic_touch_jj02_mode"
        const val PREF_HEATING = "pref_magic_touch_jj02_heating"
        const val PREF_HEAT_LEVEL = "pref_magic_touch_jj02_heat_level"
        const val PREF_TIMER = "pref_magic_touch_jj02_timer"
        const val PREF_BATTERY = "pref_magic_touch_jj02_battery"
        const val PREF_BATTERY_LEVEL = "pref_magic_touch_jj02_battery_level"



        private val AUTH_START = byteArrayOf(0xa4.toByte())

        /** Fixed LOGIN_START (verified HCI snoop). */
        private val LOGIN_START = byteArrayOf(0x24.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte())

        /** 6-byte SEND frames (7-byte variants are silently ignored by the device). */
        private val SEND_KEY = byteArrayOf(0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x0b.toByte(), 0x01.toByte(), 0x00.toByte())
        private val SEND_INFO = byteArrayOf(0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x0a.toByte(), 0x01.toByte(), 0x00.toByte())
        private val OPEN_CMD = byteArrayOf(0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x01.toByte(), 0x00.toByte())
        private val RCV_RDY = byteArrayOf(0x00.toByte(), 0x00.toByte(), 0x01.toByte(), 0x01.toByte())
        private val RCV_OK = byteArrayOf(0x00.toByte(), 0x00.toByte(), 0x01.toByte(), 0x00.toByte())
        private val ACK = byteArrayOf(0x00.toByte(), 0x00.toByte(), 0x03.toByte(), 0x00.toByte())
        private val PREFIX_DATA = byteArrayOf(0x01.toByte(), 0x00.toByte())
        private val PING = byteArrayOf(0x00.toByte(), 0x00.toByte(), 0x01.toByte(), 0x05.toByte(), 0x01.toByte(), 0x00.toByte())
        private val PONG = byteArrayOf(0x00.toByte(), 0x00.toByte(), 0x05.toByte(), 0x04.toByte(), 0x01.toByte(), 0x00.toByte())
        private val LOGIN_OK = byteArrayOf(0x21.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte())
        private val LOGIN_FAIL = byteArrayOf(0x22.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte())

        private const val HKDF_INFO = "mible-login-info"

        /** Capability/version payload the vendor app sends first after login. */
        private val BATTERY_CAP = byteArrayOf(0x05.toByte(), 0x20.toByte(), 0x02.toByte(), 0x00.toByte(), 0xf0.toByte())

        private const val TYPE_UINT8 = 0x10
    }
}

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
package nodomain.freeyourgadget.gadgetbridge.service.devices.yunmai

import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattService
import android.content.SharedPreferences
import android.widget.Toast
import nodomain.freeyourgadget.gadgetbridge.GBApplication
import nodomain.freeyourgadget.gadgetbridge.R
import nodomain.freeyourgadget.gadgetbridge.activities.devicesettings.DeviceSettingsPreferenceConst
import nodomain.freeyourgadget.gadgetbridge.devices.MiScaleWeightSampleProvider
import nodomain.freeyourgadget.gadgetbridge.devices.yunmai.YunmaiMs107Spec
import nodomain.freeyourgadget.gadgetbridge.entities.MiScaleWeightSample
import nodomain.freeyourgadget.gadgetbridge.impl.GBDevice
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
 * Yunmai MS107 scale (sold as Mijia Body Composition Scale S400).
 *
 * Xiaomi BLE StandardAuth + encrypted op channel (same family as the JJ02
 * massager; see [YunmaiMs107Spec] for the verified framing). After login the
 * support sends capability + wakeup, reads unit + work mode, and decodes the
 * op-0x07 weigh-in stream: short piid-1 strings are live weight (0.1 kg),
 * long piid-2 strings are 32-field complete records stored as weight samples.
 * User sync is intentionally not sent (cloud-sourced account list).
 * Battery has no verified wire source and is not shown.
 */
class YunmaiMs107Support : AbstractBTLESingleDeviceSupport(LOG), SharedPreferences.OnSharedPreferenceChangeListener {
    private var authStep = AuthStep.IDLE
    private var appRandom: ByteArray? = null
    private var lastDevRandom: ByteArray? = null
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
        for (service: BluetoothGattService in gatt.services) {
            for (characteristic: BluetoothGattCharacteristic in service.characteristics) {
                if (service.uuid == UUID_SERVICE_XIAOMI) {
                    characteristic.writeType = BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE
                }
            }
        }
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

        activeInstance = this
        try {
            devicePrefs().unregisterOnSharedPreferenceChangeListener(this)
        } catch (e: Exception) {
            LOG.debug("Unregister prefs listener failed: {}", e.message)
        }
        devicePrefs().registerOnSharedPreferenceChangeListener(this)

        builder.setDeviceState(GBDevice.State.INITIALIZING)

        builder.notify(UUID_CHARACTERISTIC_REPORT, true)
        builder.notify(UUID_CHARACTERISTIC_COMMAND, true)
        builder.notify(UUID_CHARACTERISTIC_DEVICE_INFO, true)
        builder.write(UUID_CHARACTERISTIC_DEVICE_INFO, 0x00.toByte())
        builder.write(UUID_CHARACTERISTIC_DEVICE_INFO, 0x03.toByte())
        builder.notify(UUID_CHARACTERISTIC_LOGIN, true)
        builder.read(UUID_CHARACTERISTIC_FIRMWARE_VERSION)
        builder.requestMtu(247)

        if (getToken() == null) {
            LOG.warn("No cloud token configured, skipping login (set it in device settings)")
            gbDevice.setUpdateState(GBDevice.State.INITIALIZED, context)
            GB.toast(context, R.string.yunmai_ms107_bind_key_summary, Toast.LENGTH_LONG, GB.WARN)
            return builder
        }

        builder.write(UUID_CHARACTERISTIC_AUTH_CTRL, *AUTH_START)
        authStep = AuthStep.EXPECT_KEY_EXCHANGE
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

    override fun onSendConfiguration(config: String) {
        if (activeInstance !== this) {
            return
        }
        if (authStep != AuthStep.DONE && config != "refresh") {
            GB.toast(context, R.string.device_not_connected, Toast.LENGTH_LONG, GB.WARN)
            return
        }
        when (config) {
            "wakeup" -> sendMiotCommand(YunmaiMs107Spec.buildWakeup(nextMsgId()))
            "refresh" -> refreshBasic()
            else -> LOG.warn("Unknown configuration key: {}", config)
        }
    }

    private fun nextMsgId(): Int {
        val id = miotMsgId and 0xffff
        miotMsgId++
        return id
    }

    private fun refreshBasic() {
        sendMiotCommand(YunmaiMs107Spec.buildCapability(nextMsgId()))
        sendMiotCommand(YunmaiMs107Spec.buildWakeup(nextMsgId()))
        sendMiotCommand(YunmaiMs107Spec.buildGet(nextMsgId(), YunmaiMs107Spec.SIID_SCALE, YunmaiMs107Spec.PIID_UNIT))
        sendMiotCommand(YunmaiMs107Spec.buildGet(nextMsgId(), YunmaiMs107Spec.SIID_WORK_MODE, YunmaiMs107Spec.PIID_WORK_MODE))
        // Plugin readDeviceBattery (siid 13/piid 10). The stock app was never
        // observed sending it and the value semantics are unknown, so the
        // reply (if any) is only logged by handleGetResult, never displayed.
        sendMiotCommand(YunmaiMs107Spec.buildGet(nextMsgId(), YunmaiMs107Spec.SIID_SYNCINFO, YunmaiMs107Spec.PIID_BATTERY))
    }

    private fun startLogin() {
        authStep = AuthStep.EXPECT_KEY_EXCHANGE
        keyExchangeEchoes = 0
        createTransactionBuilder("yunmai_ms107_start_login")
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

    private fun handleAuthCtrl(value: ByteArray) {
        when {
            value.contentEquals(LOGIN_OK) -> onLoginOk()
            value.contentEquals(LOGIN_FAIL) -> authFailed("device rejected login (LOGIN_FAIL)")
            else -> LOG.warn("Unexpected AUTH_CTRL frame in step {}: {}", authStep, GB.hexdump(value))
        }
    }

    private fun handleLoginChannel(value: ByteArray) {
        when {
            startsWith(value, 0x00, 0x00, 0x04) -> {
                if (authStep != AuthStep.EXPECT_KEY_EXCHANGE) {
                    LOG.warn("Unexpected key-exchange PDU in step {}", authStep)
                    return
                }
                val echo = byteArrayOf(0x00.toByte(), 0x00.toByte(), 0x05.toByte()) + value.copyOfRange(3, value.size)
                write(UUID_CHARACTERISTIC_LOGIN, echo)
                keyExchangeEchoes++
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
            value.contentEquals(PING) -> write(UUID_CHARACTERISTIC_LOGIN, PONG)
            else -> LOG.warn("Unhandled login-channel frame in step {}: {}", authStep, GB.hexdump(value))
        }
    }

    private fun beginLogin() {
        authStep = AuthStep.EXPECT_SEND_RDY
        createTransactionBuilder("yunmai_ms107_begin_login")
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
        refreshBasic()
    }

    private fun authFailed(reason: String) {
        LOG.error("Authentication failed: {}", reason)
        authStep = AuthStep.IDLE
        GB.toast(context, R.string.authentication_failed_check_key, Toast.LENGTH_LONG, GB.WARN)
        GBApplication.deviceService(device)?.disconnect()
    }

    fun sendMiotCommand(plaintext: ByteArray) {
        if (activeInstance !== this) {
            return
        }
        cmdQueue.addLast(plaintext)
        pumpCommandQueue()
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
            handleMiotPlaintext(counter, pt)
            try {
                gbDevice.sendDeviceUpdateIntent(context)
            } catch (e: Exception) {
                LOG.debug("sendDeviceUpdateIntent failed: {}", e.message)
            }
        } catch (e: Exception) {
            LOG.warn("Failed to decrypt report ctr={}: {}", counter, e.message)
        }
    }

    private fun handleMiotPlaintext(counter: Int, pt: ByteArray) {
        if (pt.size < 5 || pt[1] != 0x20.toByte()) {
            LOG.warn("REPORT ctr={} non-MiOT: {}", counter, GB.hexdump(pt))
            return
        }
        when (pt[4].toInt() and 0xff) {
            0x01 -> LOG.debug("REPORT ctr={} set-result: {}", counter, GB.hexdump(pt))
            0x03 -> handleGetResult(counter, pt)
            // op 0x06 action results may carry offline history (PII): length only.
            0x06 -> LOG.warn("REPORT ctr={} action-result len={}", counter, pt.size)
            0x07 -> handleOnlineData(counter, pt)
            0xF0 -> LOG.debug("REPORT ctr={} capability echo", counter)
            else -> LOG.warn("REPORT ctr={} unknown op: {}", counter, GB.hexdump(pt))
        }
    }

    private fun handleGetResult(counter: Int, pt: ByteArray) {
        // 0e 20 MM MM 03 01 SI PIlo PIhi 00 + fixed prop (00,len,type,val);
        // single-byte values (unit, mode, battery) = last byte, multi-byte
        // values are LE (see TLV in the case notes).
        if (pt.size != 14) {
            LOG.warn("REPORT ctr={} get-result len={}: {}", counter, pt.size, GB.hexdump(pt))
            return
        }
        val siid = pt[6].toInt() and 0xff
        val piid = (pt[7].toInt() and 0xff) or ((pt[8].toInt() and 0xff) shl 8)
        val v = pt[13].toInt() and 0xff
        LOG.warn("REPORT ctr={} get siid={} piid={} val={}", counter, siid, piid, v)
    }

    private fun handleOnlineData(counter: Int, pt: ByteArray) {
        // 07 08 EE 00 01 PP 00 LL A0 <ASCII> (verified): EE/PP = 01/1 realtime
        // "W,S" (0.1 kg), 02/2 complete (32 comma fields, plugin order).
        // Other siids (e.g. siid-10 balance pushes): header only.
        if (pt.size < 14 || pt[1] != 0x20.toByte() || (pt[4].toInt() and 0xff) != 0x07) {
            LOG.warn("REPORT ctr={} online-data short", counter)
            return
        }
        if ((pt[5].toInt() and 0xff) != YunmaiMs107Spec.SIID_ONLINE_DATA) {
            LOG.warn(
                "REPORT ctr={} non-scale op07 len={} siid={} head={}",
                counter, pt.size, pt[5].toInt() and 0xff, GB.hexdump(pt.copyOfRange(0, 12.coerceAtMost(pt.size))),
            )
            return
        }
        val evt = pt[6].toInt() and 0xff
        val piid = pt[9].toInt() and 0xff
        val a0 = pt.indexOf(0xa0.toByte())
        if (a0 < 0 || a0 + 1 >= pt.size) {
            LOG.warn("REPORT ctr={} online-data no string: {}", counter, GB.hexdump(pt))
            return
        }
        val str = try {
            String(pt.copyOfRange(a0 + 1, pt.size), Charsets.US_ASCII)
        } catch (e: Exception) {
            LOG.warn("REPORT ctr={} bad string", counter)
            return
        }
        if (evt == 0x01 && piid == 1) {
            val parts = str.split(',')
            val tenthKg = parts.getOrNull(0)?.toIntOrNull()
            val status = parts.getOrNull(1)?.toIntOrNull()
            if (tenthKg == null) {
                LOG.warn("REPORT ctr={} realtime unparseable: {}", counter, str)
                return
            }
            LOG.debug("REPORT ctr={} realtime {} kg status={}", counter, tenthKg / 10.0f, status)
        } else if (evt == 0x02 && piid == 2) {
            handleCompleteRecord(counter, str)
        } else {
            LOG.warn("REPORT ctr={} online-data evt={} piid={}: {}", counter, evt, piid, str)
        }
    }

    private fun handleCompleteRecord(counter: Int, str: String) {
        val f = str.split(',')
        if (f.size != YunmaiMs107Spec.COMPLETE_FIELD_COUNT) {
            LOG.warn("REPORT ctr={} complete fields={} (want 32)", counter, f.size)
            return
        }
        val tenthKg = f[YunmaiMs107Spec.COMPLETE_WEIGHT_TENTH_KG].toIntOrNull()
        val timeSec = f[YunmaiMs107Spec.COMPLETE_TIME_SEC].toLongOrNull()
        if (tenthKg == null) {
            LOG.warn("REPORT ctr={} complete bad weight", counter)
            return
        }
        var sampleTs = (timeSec ?: 0L) * 1000L
        if (sampleTs < SCALE_RELEASE_DATE || sampleTs > System.currentTimeMillis() + 86400_000L) {
            sampleTs = System.currentTimeMillis()
        }
        val weightKg = tenthKg / 10.0f
        // Impedance slot: plugin bodyRes (/10 ohms) at a wire-verified
        // position; unit mapping is plugin-sourced, so range-gated.
        // '-' sentinels (unavailable) fail toIntOrNull and stay null.
        val tenthOhm = f[YunmaiMs107Spec.COMPLETE_IMPEDANCE_TENTH_OHM].toIntOrNull()
        val impedanceOhm = tenthOhm?.div(10)?.takeIf { it in 100..1500 }
        LOG.warn("Weigh-in: {} kg impedance={} at {}", weightKg, impedanceOhm, sampleTs)
        GB.toast(context.getString(R.string.weight_kg, weightKg), Toast.LENGTH_SHORT, GB.INFO)
        try {
            val prefs = devicePrefs()
            if (!prefs.getBoolean(PREF_SMALL_OBJECTS, false) && weightKg < SMALL_OBJECT_MAX_KG) {
                LOG.debug("Skipping small-object sample {} kg", weightKg)
                return
            }
        } catch (e: Exception) {
            LOG.debug("Small-object pref read failed: {}", e.message)
        }
        try {
            GBApplication.acquireDB().use { db ->
                val provider = MiScaleWeightSampleProvider(gbDevice, db.daoSession)
                val sample = MiScaleWeightSample()
                sample.timestamp = sampleTs
                sample.weightKg = weightKg
                sample.impedanceOhm = impedanceOhm
                // HR/composition slots: no GB store target in v1.
                provider.persistSamples(sample, context)
                GB.signalActivityDataFinish(gbDevice)
            }
        } catch (e: Exception) {
            LOG.error("Error saving weight sample", e)
        }
    }

    override fun onSharedPreferenceChanged(prefs: SharedPreferences, key: String?) {
        if (activeInstance !== this) {
            return
        }
        if (key == DeviceSettingsPreferenceConst.PREF_AUTH_KEY) {
            if (isConnected() && authStep == AuthStep.IDLE) {
                LOG.warn("Token saved, starting login")
                startLogin()
            }
        }
    }

    private fun write(characteristic: UUID, data: ByteArray) {
        createTransactionBuilder("yunmai_ms107_write_$characteristic")
            .write(characteristic, *data)
            .sleep(30)
            .queue()
    }

    /**
     * 12-byte cloud token (24 hex chars) from the standard authkey slot.
     * This is the Mi Home "token", NOT a 16-byte BLE bind key.
     */
    private fun getToken(): ByteArray? {
        val prefs = GBApplication.getDeviceSpecificSharedPrefs(gbDevice.address)
        val raw = prefs?.getString(DeviceSettingsPreferenceConst.PREF_AUTH_KEY, "")?.trim() ?: ""
        if (raw.isEmpty()) {
            return null
        }
        val hex = if (raw.startsWith("0x")) raw.substring(2) else raw
        if (hex.length != 24) {
            return null
        }
        val bytes = runCatching { GB.hexStringToByteArray(hex) }.getOrNull()
        if (bytes != null && bytes.size == 12) {
            return bytes
        }
        LOG.error("No 12-byte cloud token configured (authkey slot)")
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
        private val LOG = LoggerFactory.getLogger(YunmaiMs107Support::class.java)

        private var activeInstance: YunmaiMs107Support? = null

        val UUID_SERVICE_XIAOMI: UUID = UUID.fromString(YunmaiMs107Spec.UUID_SERVICE_XIAOMI)
        val UUID_CHARACTERISTIC_AUTH_CTRL: UUID = UUID.fromString(YunmaiMs107Spec.UUID_AUTH_CTRL)
        val UUID_CHARACTERISTIC_LOGIN: UUID = UUID.fromString(YunmaiMs107Spec.UUID_LOGIN)
        val UUID_CHARACTERISTIC_COMMAND: UUID = UUID.fromString(YunmaiMs107Spec.UUID_COMMAND)
        val UUID_CHARACTERISTIC_REPORT: UUID = UUID.fromString(YunmaiMs107Spec.UUID_REPORT)
        val UUID_CHARACTERISTIC_DEVICE_INFO: UUID = UUID.fromString(YunmaiMs107Spec.UUID_DEVICE_INFO)
        val UUID_CHARACTERISTIC_FIRMWARE_VERSION: UUID = UUID.fromString(YunmaiMs107Spec.UUID_FIRMWARE_VERSION)

        const val PREF_SMALL_OBJECTS = "pref_miscale_small_objects"
        private const val SMALL_OBJECT_MAX_KG = 10.0f
        private const val SCALE_RELEASE_DATE = 1521072000000L

        private val AUTH_START = byteArrayOf(0xa4.toByte())
        private val LOGIN_START = byteArrayOf(0x24.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte())
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
    }
}

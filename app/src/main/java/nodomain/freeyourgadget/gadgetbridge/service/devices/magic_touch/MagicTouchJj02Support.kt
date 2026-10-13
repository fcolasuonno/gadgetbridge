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
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattService
import android.widget.Toast
import nodomain.freeyourgadget.gadgetbridge.GBApplication
import nodomain.freeyourgadget.gadgetbridge.R
import nodomain.freeyourgadget.gadgetbridge.impl.GBDevice
import nodomain.freeyourgadget.gadgetbridge.service.btle.AbstractBTLESingleDeviceSupport
import nodomain.freeyourgadget.gadgetbridge.service.btle.TransactionBuilder
import nodomain.freeyourgadget.gadgetbridge.service.devices.xiaomi_scooters.XiaomiScooterCrypto
import nodomain.freeyourgadget.gadgetbridge.service.devices.xiaomi_scooters.XiaomiScooterTransport
import nodomain.freeyourgadget.gadgetbridge.util.CryptoUtils
import nodomain.freeyourgadget.gadgetbridge.util.GB
import org.slf4j.LoggerFactory
import java.nio.charset.StandardCharsets
import java.security.KeyPair
import java.util.UUID

/**
 * Mijia Smart Neck and Shoulder Massager (xiaomi.magic_touch.jj02).
 *
 * The device speaks the same Xiaomi BLE secure family as the scooters: identical
 * channel UUIDs (AUTH_CTRL 0x0010, AUTH_DATA 0x0016, CMD 0x001A, REPORT 0x001B,
 * DEVICE_INFO 0x001C) and the same `00 00 ..` flow-control transport (see
 * [XiaomiScooterTransport]). Login reuses [XiaomiScooterCrypto] (ephemeral ECDH
 * P-256 + HKDF-SHA256 + AES-128-CCM), seeded with the 16-byte BLE bind key from
 * the device settings instead of the scooter's 32-byte auth key.
 *
 * The application protocol on top (miot siid/piid properties) is still being
 * decoded; every decrypted payload is logged until the mapping is confirmed.
 */
class MagicTouchJj02Support : AbstractBTLESingleDeviceSupport(LOG) {
    private var authStep = AuthStep.EXPECT_PRE_KEY_HEADER
    private lateinit var ephemeralKeyPair: KeyPair
    private var pendingLoginToken: ByteArray? = null
    private var session: XiaomiScooterCrypto.Session? = null

    /**
     * The characteristic the login replies go to: AUTH_DATA (0x0017). NOTE: this is NOT the
     * scooter's 0x0016 and NOT the 0x0019 channel the pre-key pushes arrive on -- the snoop
     * proves the 64-247 byte login frames go to value handle 0x0018, i.e. UUID 0x0017.
     * Never derived from incoming traffic; the device only listens here.
     */
    private var authDataChannel: UUID = UUID_CHARACTERISTIC_AUTH_DATA

    // GATT table, captured for the exploration log and for subscribing extras
    private var extraNotifiables: List<BluetoothGattCharacteristic> = emptyList()

    init {
        addSupportedService(UUID_SERVICE_XIAOMI)
    }

    override fun useAutoConnect(): Boolean = true

    override fun onServicesDiscovered(gatt: BluetoothGatt) {
        val sb = StringBuilder("GATT table:")
        val extras = ArrayList<BluetoothGattCharacteristic>()
        for (service: BluetoothGattService in gatt.services) {
            sb.append("\n  service ").append(service.uuid)
            for (characteristic: BluetoothGattCharacteristic in service.characteristics) {
                // The vendor app only ever uses write-commands (0x52), including on the
                // WRITE|NOTIFY characteristics: with-response writes are rejected.
                if (service.uuid == UUID_SERVICE_XIAOMI) {
                    characteristic.writeType = BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE
                }
                sb.append("\n    char ").append(characteristic.uuid)
                    .append(" props=0x").append(Integer.toHexString(characteristic.properties))
                for (descriptor: BluetoothGattDescriptor in characteristic.descriptors) {
                    sb.append(" desc=").append(descriptor.uuid)
                }
                val props = characteristic.properties
                if (characteristic.uuid != UUID_CHARACTERISTIC_AUTH_CTRL &&
                    characteristic.uuid != UUID_CHARACTERISTIC_AUTH_DATA &&
                    characteristic.uuid != UUID_CHARACTERISTIC_COMMAND &&
                    characteristic.uuid != UUID_CHARACTERISTIC_REPORT &&
                    (props and (BluetoothGattCharacteristic.PROPERTY_NOTIFY
                            or BluetoothGattCharacteristic.PROPERTY_INDICATE)) != 0
                ) {
                    extras.add(characteristic)
                }
            }
        }
        LOG.warn(sb.toString())
        extraNotifiables = extras
        super.onServicesDiscovered(gatt)
    }

    override fun initializeDevice(builder: TransactionBuilder): TransactionBuilder {
        authStep = AuthStep.EXPECT_PRE_KEY_HEADER
        ephemeralKeyPair = XiaomiScooterCrypto.generateEphemeralKeyPair()
        pendingLoginToken = null
        session = null
        authDataChannel = UUID_CHARACTERISTIC_AUTH_DATA

        builder.setDeviceState(GBDevice.State.INITIALIZING)
        builder.requestMtu(247)

        builder.notify(UUID_CHARACTERISTIC_AUTH_CTRL, true)
        builder.notify(UUID_CHARACTERISTIC_AUTH_DATA, true)
        builder.notify(UUID_CHARACTERISTIC_COMMAND, true)
        builder.notify(UUID_CHARACTERISTIC_REPORT, true)
        // Extra massager channels (0x0005 status, 0x0019 key-exchange echo, 0x001C info)
        for (characteristic in extraNotifiables) {
            builder.notify(characteristic, true)
        }

        builder.write(UUID_CHARACTERISTIC_AUTH_CTRL, *AUTH_START)
        // Version query, mirroring the vendor app (0x03 -> chip string like RTL8762C)
        builder.write(UUID_CHARACTERISTIC_DEVICE_INFO, 0x03)

        // Initialization finishes asynchronously on LOGIN_OK -- see onLoginOk().
        return builder
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

            UUID_CHARACTERISTIC_AUTH_DATA -> {
                handleAuthData(value)
                return true
            }

            UUID_CHARACTERISTIC_COMMAND -> {
                LOG.warn("CMD {}: {}", characteristic.uuid, GB.hexdump(value))
                return true
            }

            UUID_CHARACTERISTIC_KEY_EXCHANGE -> {
                LOG.debug("Key-exchange channel frame: {}", GB.hexdump(value))
                handleAuthData(value)
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
    // Login handshake (ported from the scooter support)
    // =======================================================================

    private fun handleAuthCtrl(value: ByteArray) {
        if (authStep == AuthStep.EXPECT_LOGIN_OK && value.contentEquals(LOGIN_OK)) {
            onLoginOk()
        } else if (value.contentEquals(LOGIN_FAIL)) {
            LOG.error("Authentication failed, disconnecting")
            GB.toast(context, R.string.authentication_failed_check_key, Toast.LENGTH_LONG, GB.WARN)
            GBApplication.deviceService(device)?.disconnect()
        } else {
            LOG.warn("Unexpected AUTH_CTRL frame in step {}: {}", authStep, GB.hexdump(value))
        }
    }

    private fun handleAuthData(value: ByteArray) {
        when (val frame = XiaomiScooterTransport.parse(value)) {
            is XiaomiScooterTransport.ParsedFrame.KeyExchange -> {
                if (frame.fromDevice && authStep == AuthStep.EXPECT_PRE_KEY_HEADER) {
                    LOG.debug("Got pre-key header, replaying response")
                    replayKeyExchange(value)
                    authStep = AuthStep.EXPECT_PRE_KEY_DATA
                } else if (frame.fromDevice && authStep == AuthStep.EXPECT_PRE_KEY_DATA) {
                    LOG.debug("Got pre-key data, starting login")
                    replayKeyExchange(value)
                    beginPublicKeyExchange()
                } else {
                    LOG.warn("Unexpected key-exchange PDU in step {}", authStep)
                }
            }

            is XiaomiScooterTransport.ParsedFrame.RcvRdy -> when (authStep) {
                AuthStep.EXPECT_APP_PUBKEY_RDY -> {
                    LOG.debug("Got RCV_RDY, sending public key")
                    write(
                        authDataChannel, XiaomiScooterTransport.buildDataFrame(
                            XiaomiScooterCrypto.publicKeyToRaw(ephemeralKeyPair.public)
                        )
                    )
                    authStep = AuthStep.EXPECT_APP_PUBKEY_OK
                }

                AuthStep.EXPECT_TOKEN_RDY -> {
                    val token = pendingLoginToken
                    if (token == null) {
                        LOG.error("Got RCV_RDY on {}, but login token is null", authStep)
                        return
                    }
                    LOG.debug("Got RCV_RDY, sending login token")
                    write(authDataChannel, XiaomiScooterTransport.buildDataFrame(token))
                    authStep = AuthStep.EXPECT_TOKEN_OK
                }

                else -> LOG.warn("Unexpected RCV_RDY in auth step {}", authStep)
            }

            is XiaomiScooterTransport.ParsedFrame.RcvOk -> when (authStep) {
                AuthStep.EXPECT_APP_PUBKEY_OK -> authStep = AuthStep.EXPECT_DEVICE_PUBKEY
                AuthStep.EXPECT_TOKEN_OK -> authStep = AuthStep.EXPECT_LOGIN_OK
                else -> LOG.warn("Unexpected RCV_OK in auth step {}", authStep)
            }

            is XiaomiScooterTransport.ParsedFrame.Data -> {
                if (frame.type == XiaomiScooterTransport.TYPE_DEV_PUBKEY && authStep == AuthStep.EXPECT_DEVICE_PUBKEY) {
                    onDevicePublicKey(frame.payload)
                } else {
                    LOG.warn(
                        "Unexpected AUTH_DATA data frame (type=0x{}) in step {}: {}",
                        Integer.toHexString(frame.type),
                        authStep,
                        GB.hexdump(value)
                    )
                }
            }

            else -> LOG.warn("Unhandled AUTH_DATA frame in auth step {}: {}", authStep, frame)
        }
    }

    private fun handleReport(value: ByteArray) {
        val frame = XiaomiScooterTransport.parse(value)
        LOG.warn("REPORT {}: {}", frame, GB.hexdump(value))
        if (frame is XiaomiScooterTransport.ParsedFrame.Data && authStep == AuthStep.DONE) {
            decryptAndLog(frame.payload)
        }
    }

    /**
     * The device emits pre-key pushes on either 0x0017 or 0x0019 depending on the session,
     * but only listens for the replay on one of them; replay on both (idempotent).
     */
    private fun replayKeyExchange(deviceFrame: ByteArray) {
        val replay = XiaomiScooterTransport.replayKeyExchangePdu(deviceFrame)
        write(authDataChannel, replay)
        write(UUID_CHARACTERISTIC_KEY_EXCHANGE, replay)
    }

    private fun beginPublicKeyExchange() {
        write(UUID_CHARACTERISTIC_AUTH_CTRL, LOGIN_START)
        write(authDataChannel, XiaomiScooterTransport.buildSend(XiaomiScooterTransport.TYPE_DEV_PUBKEY))
        authStep = AuthStep.EXPECT_APP_PUBKEY_RDY
    }

    private fun onDevicePublicKey(devicePubKey: ByteArray) {
        LOG.debug("Got device public key, preparing to send login token")

        write(authDataChannel, XiaomiScooterTransport.ACK)

        val bindKey = getBindKey()
        if (bindKey == null) {
            LOG.error("No BLE bind key configured, cannot log in")
            return
        }

        val sharedSecret = XiaomiScooterCrypto.sharedSecret(ephemeralKeyPair.private, devicePubKey)
        val sessionKeys = deriveSessionKeys16(sharedSecret, bindKey)

        LOG.debug(
            "Derived session keys devKey={} appKey={} devIv={} appIv={}",
            GB.hexdump(sessionKeys.devKey),
            GB.hexdump(sessionKeys.appKey),
            GB.hexdump(sessionKeys.devIv),
            GB.hexdump(sessionKeys.appIv)
        )

        session = XiaomiScooterCrypto.Session(sessionKeys)
        pendingLoginToken = XiaomiScooterCrypto.buildLoginConfirmationToken(sessionKeys.appKey, devicePubKey)

        write(
            authDataChannel,
            XiaomiScooterTransport.buildSend(XiaomiScooterTransport.TYPE_DEV_LOGIN_INFO)
        )
        authStep = AuthStep.EXPECT_TOKEN_RDY
    }

    private fun onLoginOk() {
        LOG.warn("Login successful, session established")
        authStep = AuthStep.DONE
        getDevice().setFirmwareVersion("N/A")
        getDevice().setFirmwareVersion2("N/A")
        gbDevice.setUpdateState(GBDevice.State.INITIALIZED, context)
    }

    private fun decryptAndLog(payload: ByteArray) {
        val activeSession = session
        if (activeSession == null) {
            LOG.warn("Encrypted payload with no session: {}", GB.hexdump(payload))
            return
        }
        try {
            // Wire format guess: [counter u16-LE][ciphertext]; gb logs will confirm or refute
            if (payload.size < 2) {
                return
            }
            val counter = (payload[0].toInt() and 0xff) or ((payload[1].toInt() and 0xff) shl 8)
            val plaintext = activeSession.decryptFromDevice(counter, payload.copyOfRange(2, payload.size))
            LOG.warn("DECRYPTEDNZ report ctr={}: {}", counter, GB.hexdump(plaintext))
        } catch (e: Exception) {
            LOG.warn("Failed to decrypt report payload: {} ({})", GB.hexdump(payload), e.message)
        }
    }

    private fun getBindKey(): ByteArray? {
        val prefs = GBApplication.getDeviceSpecificSharedPrefs(gbDevice.address)
        val raw = prefs?.getString(PREF_MAGIC_TOUCH_BIND_KEY, "")?.trim() ?: return null
        val hex = if (raw.startsWith("0x")) raw.substring(2) else raw
        if (hex.length != 32) {
            LOG.error("Bind key must be 32 hex chars (16 bytes), got {}", hex.length)
            return null
        }
        return runCatching { GB.hexStringToByteArray(hex) }.getOrNull()
    }

    /**
     * Same KDF as [XiaomiScooterCrypto.deriveSessionKeys], but seeded with the
     * 16-byte BLE bind key instead of the scooter's 32-byte auth key (HKDF
     * accepts arbitrary-length key material; the device verdict will confirm).
     */
    private fun deriveSessionKeys16(ecdhSharedSecret: ByteArray, bindKey: ByteArray): XiaomiScooterCrypto.SessionKeys {
        require(ecdhSharedSecret.size == 32) { "ECDH shared secret must be 32 bytes" }
        require(bindKey.size == 16) { "Bind key must be 16 bytes" }
        val ikm = ecdhSharedSecret + bindKey
        val okm = CryptoUtils.hkdfSha256(
            ikm,
            "smartcfg-login-salt".toByteArray(StandardCharsets.US_ASCII),
            "smartcfg-login-info".toByteArray(StandardCharsets.US_ASCII),
            64,
        )
        return XiaomiScooterCrypto.SessionKeys(
            devKey = okm.copyOfRange(0, 16),
            appKey = okm.copyOfRange(16, 32),
            devIv = okm.copyOfRange(32, 36),
            appIv = okm.copyOfRange(36, 40),
        )
    }

    private fun write(characteristic: UUID, data: ByteArray) {
        createTransactionBuilder("magic_touch_write_$characteristic")
            .write(characteristic, *data)
            .sleep(30)
            .queue()
    }

    private enum class AuthStep {
        EXPECT_PRE_KEY_HEADER,
        EXPECT_PRE_KEY_DATA,
        EXPECT_APP_PUBKEY_RDY,
        EXPECT_APP_PUBKEY_OK,
        EXPECT_DEVICE_PUBKEY,
        EXPECT_TOKEN_RDY,
        EXPECT_TOKEN_OK,
        EXPECT_LOGIN_OK,
        DONE,
    }

    companion object {
        private val LOG = LoggerFactory.getLogger(MagicTouchJj02Support::class.java)

        val UUID_SERVICE_XIAOMI: UUID = UUID.fromString("0000fe95-0000-1000-8000-00805f9b34fb")
        val UUID_CHARACTERISTIC_AUTH_CTRL: UUID = UUID.fromString("00000010-0000-1000-8000-00805f9b34fb")
        /**
         * App-to-device login channel. NOTE: this is 0x0017 here, not the scooter's 0x0016:
         * the snoop proves the 64-247 byte login frames (pubkey, token) go to the characteristic
         * whose value handle is 0x0018, i.e. UUID 0x0017. The device pushes pre-key PDUs on 0x0019.
         */
        val UUID_CHARACTERISTIC_AUTH_DATA: UUID = UUID.fromString("00000017-0000-1000-8000-00805f9b34fb")
        /** The device emits the key-exchange PDUs here instead of AUTH_DATA. */
        val UUID_CHARACTERISTIC_KEY_EXCHANGE: UUID = UUID.fromString("00000019-0000-1000-8000-00805f9b34fb")
        val UUID_CHARACTERISTIC_COMMAND: UUID = UUID.fromString("0000001a-0000-1000-8000-00805f9b34fb")
        val UUID_CHARACTERISTIC_REPORT: UUID = UUID.fromString("0000001b-0000-1000-8000-00805f9b34fb")
        val UUID_CHARACTERISTIC_DEVICE_INFO: UUID = UUID.fromString("0000001c-0000-1000-8000-00805f9b34fb")

        const val PREF_MAGIC_TOUCH_BIND_KEY = "pref_magic_touch_jj02_bind_key"

        private val AUTH_START = byteArrayOf(0xa4.toByte())
        /** Captured from the vendor app (scooter uses 0x20 here); 4th byte truncated, trying 0x00. */
        private val LOGIN_START = byteArrayOf(0x24.toByte(), 0x00, 0x00, 0x00)
        private val LOGIN_OK = byteArrayOf(0x21, 0x00, 0x00, 0x00)
        private val LOGIN_FAIL = byteArrayOf(0x22, 0x00, 0x00, 0x00)
    }
}

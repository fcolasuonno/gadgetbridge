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
package nodomain.freeyourgadget.gadgetbridge.devices.yunmai;

/**
 * Yunmai MS107 scale (sold as Mijia Body Composition Scale S400) wire constants.
 *
 * <p>Transport is the Xiaomi BLE StandardAuth + encrypted op-channel family
 * (same as MagicTouch JJ02: login UUID 0x19 both directions, CMD 0x1a,
 * REPORT 0x1b, HKDF-SHA256 over the 12-byte cloud token with
 * {@code "mible-login-info"}, AES-CCM 4-byte tag). Verified live against the
 * S400: login, wakeup, property gets, offline request, weigh-in stream.
 *
 * <p>Op channel plaintext layout (verified live + vendor HCI: 62/62 frames,
 * 5/5 sessions): {@code LL 20 MM MM OP ...} where {@code LL} is the length
 * byte, {@code MM MM} the LE message id and {@code OP = plaintext[4]}:
 * <ul>
 *   <li>CMD op {@code 0x00}: set-properties
 *       ({@code 0c 20 MM MM 00 01 SI PI 00 01 T V}, 12 B). The app drives
 *       siid-10 mode around measurements; Gadgetbridge does not send sets.</li>
 *   <li>CMD op {@code 0x02}: property gets
 *       ({@code 09 20 MM MM 02 01 SI PIlo PIhi}, 9 B).</li>
 *   <li>CMD op {@code 0x05}: actions ({@code LL 20 MM MM 05 SI AI NN ...},
 *       NN = arg count): wakeup = siid 10/aiid 1/no args (8 B); user sync =
 *       siid 13/aiid 1 with 5 typed props incl. the user-list JSON (197 B,
 *       cloud-sourced — Gadgetbridge never sends it).</li>
 *   <li>CMD op {@code 0xF0}: capability ({@code 05 20 MM MM F0}, echoed).</li>
 *   <li>TEL op {@code 0x01}: set results
 *       ({@code 0b 20 MM MM 01 01 SI AI 00 00 00}, 11 B).</li>
 *   <li>TEL op {@code 0x03}: get results
 *       ({@code 0e 20 MM MM 03 01 SI PIlo PIhi 00 00 01 10 VV}, 14 B,
 *       value = last byte).</li>
 *   <li>TEL op {@code 0x06}: action results: wakeup =
 *       {@code 07 20 MM MM 06 00 00} (7 B); sync reply = 82 B binary.</li>
 *   <li>TEL op {@code 0x07}: siid-8 online-data: fixed header
 *       {@code 07 08 EE 00 01 PP 00}, then length + {@code 0xA0} + ASCII
 *       comma string. {@code EE}/{@code PP} = {@code 01}/{@code 1} realtime
 *       ({@code "W,S"} weight in 0.1 kg, status digit) or {@code 02}/{@code 2}
 *       complete (32 comma fields in plugin MeasureComplete order:
 *       miid, duid, userType, weight/10, heartRate, status, time, bfp/10,
 *       ... 32 total). siid-10 balance pushes (20 B) are logged, not parsed.</li>
 * </ul>
 *
 * <p>Negative acks (op {@code 0x01} ending {@code 01 5E F0}, op {@code 0x06}
 * ending {@code 5D F0}) were seen only for hand-built framings the stock app
 * never sends; success acks end {@code 00 00 00}.
 *
 * <p>Weight units: realtime and complete weight fields are 0.1 kg
 * (plugin divides by 10; confirmed live against a body weigh-in).
 * Complete-record field positions follow the plugin {@code parseEventData}
 * order (structure-verified: 32 fields); per-field unit mapping is
 * plugin-sourced. Impedance/HR slots are NOT verified on the wire and are
 * not stored.
 */
public final class YunmaiMs107Spec {
    private YunmaiMs107Spec() {
    }

    /** Service FE95 + StandardAuth/operation characteristics (same as JJ02). */
    public static final String UUID_SERVICE_XIAOMI = "0000fe95-0000-1000-8000-00805f9b34fb";
    public static final String UUID_AUTH_CTRL = "00000010-0000-1000-8000-00805f9b34fb";
    public static final String UUID_LOGIN = "00000019-0000-1000-8000-00805f9b34fb";
    public static final String UUID_COMMAND = "0000001a-0000-1000-8000-00805f9b34fb";
    public static final String UUID_REPORT = "0000001b-0000-1000-8000-00805f9b34fb";
    public static final String UUID_DEVICE_INFO = "0000001c-0000-1000-8000-00805f9b34fb";
    public static final String UUID_FIRMWARE_VERSION = "00000004-0000-1000-8000-00805f9b34fb";

    /** siid 10, aiid 1, no args (plugin {@code wakeupDevice}). */
    public static final int SIID_WORK_MODE = 10;
    public static final int AIID_WAKEUP = 1;
    /** siid 9 offline-data: aiid 1 request (piid 4 = count), aiid 2 end (piid 2 = idx string). */
    public static final int SIID_OFFLINE_DATA = 9;
    /** siid 2 scale props of interest: piid 1 unit, piid 2 heart-rate switch. */
    public static final int SIID_SCALE = 2;
    public static final int PIID_UNIT = 1;
    /** siid 10 piid 1 work mode (0 Regular, 1 Baby, 2 Balance, 3 Visitor, 4 Once). */
    public static final int PIID_WORK_MODE = 1;
    /** siid 13 syncinfo piid 10 battery (plugin readDeviceBattery; wire reply unobserved). */
    public static final int SIID_SYNCINFO = 13;
    public static final int PIID_BATTERY = 10;
    /** siid 8 online-data: piid 1 weight-data, piid 2 body-composition. */
    public static final int SIID_ONLINE_DATA = 8;

    // ---- Full endpoint map (plugin-verified shapes; send paths exist only
    // ---- where the wire framing is verified: no-arg actions, cap, gets).
    // siid 1 device-info: piid 1 manufacturer, 2 model, 3 device ID,
    // 4 firmware (readDeviceInfo reads 4+5), 5 serial.
    public static final int SIID_DEVICE_INFO = 1;
    // siid 2 scale: piid 1 unit, 2 heart-rate switch, 3 time,
    // 1042 fault (0 none, 1 ble, 2 weight, 3 fat, 4 heart-rate).
    public static final int PIID_HEART_RATE_SW = 2;
    public static final int PIID_TIME = 3;
    public static final int PIID_FAULT = 1042;
    // siid 6 user-mgmt actions: 1 update-user, 2 query-update-user,
    // 3 del-user, 4 request-user-list, 5 update-base-weight, 6 switch-user.
    // Props: 1 miid, 2 age, 3 sex, 4 type, 5 height, 6 weight (0.1 kg),
    // 7 time, 8 duid, 9 bfp, 10 app version, 11 idx, 12 hash, 13 owner,
    // 14 user-status, 15 user-count.
    public static final int SIID_USER_MGMT = 6;
    public static final int AIID_UPDATE_USER = 1;
    public static final int AIID_DELETE_USER = 3;
    public static final int AIID_UPDATE_BASE_WEIGHT = 5;
    public static final int AIID_SWITCH_USER = 6;
    // siid 9 offline-data actions: 1 request (piid 4 count), 2 end (piid 2 idx
    // string). Props: 1 report, 2 idx-string, 3 count, 4 only-upload-count.
    public static final int AIID_REQUEST_OFFLINE = 1;
    public static final int AIID_END_RECEPTION = 2;
    // siid 10 work-mode props: 2 status, 3 balance-time (s), 4 real-weight.
    public static final int PIID_WORK_STATUS = 2;
    public static final int PIID_BALANCE_TIME = 3;
    public static final int PIID_REAL_WEIGHT = 4;
    // siid 11 custom BLE: piid 1 duid, 2 impedance/HR/weight u32, 3 time u32;
    // event 1022 (9 B max). siid 13 syncinfo props: 1 pkg version, 2 unit,
    // 3 HR switch, 4 time, 5 user-list JSON; results 6 offline-count, 7 SN,
    // 8 MAC, 9 FW, 10 battery. siid 14 share-cancel (aiid 1).
    // siid 15 self-check: piid 2 results string.
    public static final int SIID_CUSTOM_BLE = 11;
    public static final int PIID_OFFLINE_COUNT = 6;

    /** Complete-record field indexes (plugin MeasureComplete order). */
    public static final int COMPLETE_WEIGHT_TENTH_KG = 3;
    public static final int COMPLETE_TIME_SEC = 6;
    /** Body impedance slot (plugin bodyRes, /10 ohms; unit plugin-sourced). */
    public static final int COMPLETE_IMPEDANCE_TENTH_OHM = 30;
    public static final int COMPLETE_FIELD_COUNT = 32;

    /** Build the 8-byte wakeup action (op 0x05, siid 10 aiid 1, no args). msgId is patched by the caller. */
    public static byte[] buildWakeup(final int msgId) {
        return new byte[]{
                0x08, 0x20,
                (byte) (msgId & 0xff), (byte) ((msgId >> 8) & 0xff),
                0x05, 0x0a, 0x01, 0x00,
        };
    }

    /** Build the 5-byte capability ping (op 0xF0, echoed by the device). */
    public static byte[] buildCapability(final int msgId) {
        return new byte[]{
                0x05, 0x20,
                (byte) (msgId & 0xff), (byte) ((msgId >> 8) & 0xff),
                (byte) 0xf0,
        };
    }

    /** Build a 9-byte single-property get (op 0x02). */
    public static byte[] buildGet(final int msgId, final int siid, final int piid) {
        return new byte[]{
                0x09, 0x20,
                (byte) (msgId & 0xff), (byte) ((msgId >> 8) & 0xff),
                0x02, 0x01,
                (byte) siid, (byte) (piid & 0xff), (byte) ((piid >> 8) & 0xff),
        };
    }

    // Note: no offline-request builder. The stock app was never observed
    // requesting siid-9 offline data in 5 captured sessions (offline records
    // arrive unprompted after user sync); hand-built siid-9 framings are
    // rejected by the device. Offline-record parsing is future work.
}

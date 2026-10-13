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
package nodomain.freeyourgadget.gadgetbridge.devices.magic_touch;

import androidx.annotation.NonNull;

import java.util.regex.Pattern;

import nodomain.freeyourgadget.gadgetbridge.R;
import nodomain.freeyourgadget.gadgetbridge.devices.AbstractBLEDeviceCoordinator;
import nodomain.freeyourgadget.gadgetbridge.devices.DeviceCoordinator;
import nodomain.freeyourgadget.gadgetbridge.impl.GBDevice;
import nodomain.freeyourgadget.gadgetbridge.service.DeviceSupport;
import nodomain.freeyourgadget.gadgetbridge.service.devices.magic_touch.MagicTouchJj02Support;

/**
 * Mijia Smart Neck and Shoulder Massager (xiaomi.magic_touch.jj02).
 *
 * <p>Work in progress: discovery only. The device advertises as
 * {@code xiaomi.magic_touch.jj02} and speaks the Xiaomi miot BLE protocol
 * (see {@link MagicTouchMiotSpec}). The command channel is still being
 * reverse-engineered from HCI snoop captures; the support class currently
 * connects, dumps the GATT table and logs all notifications.
 */
public class MagicTouchJj02Coordinator extends AbstractBLEDeviceCoordinator {
    @Override
    protected Pattern getSupportedDeviceName() {
        return Pattern.compile("^xiaomi\\.magic_touch\\.jj02.*");
    }

    @Override
    public int getDeviceNameResource() {
        return R.string.devicetype_magic_touch_jj02;
    }

    @Override
    public String getManufacturer() {
        return "Xiaomi";
    }

    @Override
    public int getBondingStyle() {
        // No bonding: the vendor app never pairs (zero SMP packets in captures)
        // and the device rejects pairing attempts. All writes are commands
        // (write-without-response), like the vendor app.
        return BONDING_STYLE_NONE;
    }

    @Override
    public boolean isExperimental() {
        return true;
    }

    @Override
    public DeviceCoordinator.DeviceKind getDeviceKind(@NonNull GBDevice device) {
        return DeviceCoordinator.DeviceKind.UNKNOWN;
    }

    @NonNull
    @Override
    public Class<? extends DeviceSupport> getDeviceSupportClass(final GBDevice device) {
        return MagicTouchJj02Support.class;
    }

    @Override
    public int[] getSupportedDeviceSpecificSettings(final GBDevice device) {
        return new int[]{
                R.xml.devicesettings_magic_touch_jj02,
        };
    }
}

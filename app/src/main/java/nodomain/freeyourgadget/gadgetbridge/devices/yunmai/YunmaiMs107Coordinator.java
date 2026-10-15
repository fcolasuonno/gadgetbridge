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

import androidx.annotation.NonNull;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

import de.greenrobot.dao.AbstractDao;
import de.greenrobot.dao.Property;
import nodomain.freeyourgadget.gadgetbridge.R;
import nodomain.freeyourgadget.gadgetbridge.devices.AbstractBLEDeviceCoordinator;
import nodomain.freeyourgadget.gadgetbridge.devices.DeviceCoordinator;
import nodomain.freeyourgadget.gadgetbridge.devices.MiScaleWeightSampleProvider;
import nodomain.freeyourgadget.gadgetbridge.devices.TimeSampleProvider;
import nodomain.freeyourgadget.gadgetbridge.entities.DaoSession;
import nodomain.freeyourgadget.gadgetbridge.entities.MiScaleWeightSampleDao;
import nodomain.freeyourgadget.gadgetbridge.impl.GBDevice;
import nodomain.freeyourgadget.gadgetbridge.model.WeightSample;
import nodomain.freeyourgadget.gadgetbridge.service.DeviceSupport;
import nodomain.freeyourgadget.gadgetbridge.service.devices.yunmai.YunmaiMs107Support;

/**
 * Yunmai MS107 scale (sold as Mijia Body Composition Scale S400).
 *
 * <p>Advertises as {@code Mijia Scale S400 ...} on service FE95 and speaks
 * Xiaomi BLE StandardAuth + encrypted op channel (see {@link YunmaiMs107Spec}).
 * Login needs the 12-byte Mi Home cloud token (device settings); weigh-ins
 * are then decoded from the encrypted stream and stored as weight samples.
 */
public class YunmaiMs107Coordinator extends AbstractBLEDeviceCoordinator {
    @Override
    public Map<AbstractDao<?, ?>, Property> getAllDeviceDao(@NonNull final DaoSession session) {
        final Map<AbstractDao<?, ?>, Property> map = new HashMap<>(1);
        map.put(session.getMiScaleWeightSampleDao(), MiScaleWeightSampleDao.Properties.DeviceId);
        return map;
    }

    @Override
    protected Pattern getSupportedDeviceName() {
        return Pattern.compile("^Mijia Scale S400.*");
    }

    @NonNull
    @Override
    public Class<? extends DeviceSupport> getDeviceSupportClass(final GBDevice device) {
        return YunmaiMs107Support.class;
    }

    @Override
    public int getDeviceNameResource() {
        return R.string.devicetype_yunmai_ms107;
    }

    @Override
    public String getManufacturer() {
        return "Yunmai";
    }

    @Override
    public int getBondingStyle() {
        // No bonding, ever (zero SMP in captures); all writes are commands.
        return BONDING_STYLE_NONE;
    }

    @Override
    public boolean isExperimental() {
        return true;
    }

    @Override
    public DeviceKind getDeviceKind(@NonNull GBDevice device) {
        return DeviceCoordinator.DeviceKind.SCALE;
    }

    @Override
    public int getBatteryCount(final GBDevice device) {
        // No verified battery source on the wire yet.
        return 0;
    }

    @Override
    public TimeSampleProvider<? extends WeightSample> getWeightSampleProvider(final GBDevice device, final DaoSession session) {
        return new MiScaleWeightSampleProvider(device, session);
    }

    @Override
    public boolean supportsWeightMeasurement(@NonNull GBDevice device) {
        return true;
    }

    @Override
    public boolean supportsCharts(@NonNull GBDevice device) {
        return true;
    }

    @Override
    public boolean requiresAuthKey() {
        // 12-byte Mi Home cloud token, entered at discovery or later in settings.
        return true;
    }

    @Override
    public boolean validateAuthKey(@NonNull final String authKey) {
        String hex = authKey.trim();
        if (hex.startsWith("0x") || hex.startsWith("0X")) {
            hex = hex.substring(2);
        }
        if (hex.length() != 24) {
            return false;
        }
        for (int i = 0; i < hex.length(); i++) {
            char c = hex.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                return false;
            }
        }
        return true;
    }

    @Override
    public int[] getSupportedDeviceSpecificSettings(final GBDevice device) {
        return new int[]{
                R.xml.devicesettings_yunmai_ms107,
        };
    }
}

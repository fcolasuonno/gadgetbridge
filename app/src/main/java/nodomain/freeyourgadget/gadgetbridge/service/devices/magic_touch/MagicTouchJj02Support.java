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
package nodomain.freeyourgadget.gadgetbridge.service.devices.magic_touch;

import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattDescriptor;
import android.bluetooth.BluetoothGattService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import nodomain.freeyourgadget.gadgetbridge.impl.GBDevice;
import nodomain.freeyourgadget.gadgetbridge.service.btle.AbstractBTLESingleDeviceSupport;
import nodomain.freeyourgadget.gadgetbridge.service.btle.TransactionBuilder;
import nodomain.freeyourgadget.gadgetbridge.util.GB;

/**
 * Mijia Smart Neck and Shoulder Massager (xiaomi.magic_touch.jj02).
 *
 * <p>EXPLORATION STAGE: connects, dumps the full GATT table (service and
 * characteristic UUIDs with properties), subscribes to every notifiable
 * characteristic and logs all incoming data with full bytes. No commands are
 * sent yet; the miot command channel is being reverse-engineered from HCI
 * snoop captures of the vendor app.
 */
public class MagicTouchJj02Support extends AbstractBTLESingleDeviceSupport {
    private static final Logger LOG = LoggerFactory.getLogger(MagicTouchJj02Support.class);

    private static final UUID CCC_UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb");

    public static final String PREF_MAGIC_TOUCH_BIND_KEY = "pref_magic_touch_jj02_bind_key";

    private List<BluetoothGattCharacteristic> notifiables = new ArrayList<>();

    public MagicTouchJj02Support() {
        super(LOG);
    }

    @Override
    public boolean useAutoConnect() {
        return true;
    }

    @Override
    public void onServicesDiscovered(final BluetoothGatt gatt) {
        final StringBuilder sb = new StringBuilder("GATT table:");
        notifiables = new ArrayList<>();
        for (final BluetoothGattService service : gatt.getServices()) {
            sb.append("\n  service ").append(service.getUuid());
            for (final BluetoothGattCharacteristic characteristic : service.getCharacteristics()) {
                sb.append("\n    char ").append(characteristic.getUuid())
                        .append(" props=0x").append(Integer.toHexString(characteristic.getProperties()));
                for (final BluetoothGattDescriptor descriptor : characteristic.getDescriptors()) {
                    sb.append(" desc=").append(descriptor.getUuid());
                }
                final int props = characteristic.getProperties();
                if ((props & (BluetoothGattCharacteristic.PROPERTY_NOTIFY
                        | BluetoothGattCharacteristic.PROPERTY_INDICATE)) != 0) {
                    notifiables.add(characteristic);
                }
            }
        }
        LOG.warn(sb.toString());
        super.onServicesDiscovered(gatt);
    }

    @Override
    protected TransactionBuilder initializeDevice(final TransactionBuilder builder) {
        builder.setDeviceState(GBDevice.State.INITIALIZING);
        builder.requestMtu(247);
        if (hasValidBindKey()) {
            LOG.warn("BLE bind key present, command channel can be encrypted once decoded");
        } else {
            LOG.warn("BLE bind key missing or invalid, enter the 32 hex characters in the device settings");
        }
        for (final BluetoothGattCharacteristic characteristic : notifiables) {
            LOG.warn("Subscribing to {}", characteristic.getUuid());
            builder.notify(characteristic, true);
        }
        getDevice().setFirmwareVersion("N/A");
        getDevice().setFirmwareVersion2("N/A");
        builder.setDeviceState(GBDevice.State.INITIALIZED);
        return builder;
    }

    @Override
    public boolean onCharacteristicChanged(final BluetoothGatt gatt,
                                           final BluetoothGattCharacteristic characteristic,
                                           final byte[] value) {
        super.onCharacteristicChanged(gatt, characteristic, value);
        LOG.warn("NOTIFY {} len={}: {}", characteristic.getUuid(),
                value != null ? value.length : -1, GB.hexdump(value));
        return true;
    }

    private boolean hasValidBindKey() {
        final String bindKey = getDevicePrefs().getString(PREF_MAGIC_TOUCH_BIND_KEY, null);
        return bindKey != null && bindKey.matches("[0-9a-fA-F]{32}");
    }
}

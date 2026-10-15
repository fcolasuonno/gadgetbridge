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
package nodomain.freeyourgadget.gadgetbridge.devices.yunmai

import nodomain.freeyourgadget.gadgetbridge.GBApplication
import nodomain.freeyourgadget.gadgetbridge.R
import nodomain.freeyourgadget.gadgetbridge.devices.DeviceCardAction
import nodomain.freeyourgadget.gadgetbridge.devices.deviceCardAction
import nodomain.freeyourgadget.gadgetbridge.service.devices.yunmai.YunmaiMs107Support

fun yunmaiMs107CustomActions(): List<DeviceCardAction> = listOf(
    deviceCardAction {
        id = "yunmai_ms107_wakeup"
        icon = { R.drawable.ic_alarm_smart_wake }
        description = { _, context -> context.getString(R.string.yunmai_ms107_action_wakeup) }
        isVisible = { device -> device.isInitialized }
        onClick = { device, _ ->
            GBApplication.deviceService(device)?.onSendConfiguration("wakeup")
        }
    },
    deviceCardAction {
        id = "yunmai_ms107_refresh"
        icon = { R.drawable.ic_refresh }
        description = { _, context -> context.getString(R.string.yunmai_ms107_action_refresh) }
        isVisible = { device -> device.isInitialized }
        onClick = { device, _ ->
            GBApplication.deviceService(device)?.onSendConfiguration("refresh")
        }
    },
    deviceCardAction {
        id = "yunmai_ms107_offline_check"
        icon = { R.drawable.ic_download }
        description = { device, context ->
            val count = try {
                GBApplication.getDeviceSpecificSharedPrefs(device.address)
                    .getInt(YunmaiMs107Support.PREF_OFFLINE_COUNT, -1)
            } catch (e: Exception) {
                -1
            }
            if (count >= 0) {
                context.getString(R.string.yunmai_ms107_action_offline_known, count)
            } else {
                context.getString(R.string.yunmai_ms107_action_offline)
            }
        }
        isVisible = { device -> device.isInitialized }
        onClick = { device, _ ->
            GBApplication.deviceService(device)?.onSendConfiguration("offline_check")
        }
    },
)

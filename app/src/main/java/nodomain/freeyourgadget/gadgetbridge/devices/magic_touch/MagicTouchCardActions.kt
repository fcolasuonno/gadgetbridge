package nodomain.freeyourgadget.gadgetbridge.devices.magic_touch

import nodomain.freeyourgadget.gadgetbridge.GBApplication
import nodomain.freeyourgadget.gadgetbridge.R
import nodomain.freeyourgadget.gadgetbridge.devices.DeviceCardAction
import nodomain.freeyourgadget.gadgetbridge.devices.deviceCardAction
import nodomain.freeyourgadget.gadgetbridge.impl.GBDevice
import nodomain.freeyourgadget.gadgetbridge.service.devices.magic_touch.MagicTouchJj02Support

private fun isPowerOn(device: GBDevice): Boolean =
    GBApplication.getDeviceSpecificSharedPrefs(device.address)
        .getBoolean(MagicTouchJj02Support.PREF_POWER, false)

private fun sendConfig(device: GBDevice, key: String) {
    GBApplication.deviceService(device)?.onSendConfiguration(key)
}

fun magicTouchCustomActions(): List<DeviceCardAction> = listOf(
    deviceCardAction {
        id = "magic_touch_power"
        icon = { R.drawable.ic_power_settings_new }
        description = { _, context -> context.getString(R.string.magic_touch_jj02_power_title) }
        isVisible = { it.isInitialized }
        onClick = { device, _ -> sendConfig(device, "power_toggle") }
    },
    deviceCardAction {
        id = "magic_touch_mode"
        icon = { R.drawable.ic_mode_fan }
        description = { _, context -> context.getString(R.string.magic_touch_jj02_mode_title) }
        isVisible = { it.isInitialized && isPowerOn(it) }
        onClick = { device, _ -> sendConfig(device, "mode_next") }
    },
    deviceCardAction {
        id = "magic_touch_heating"
        icon = { R.drawable.ic_mode_heat }
        description = { _, context -> context.getString(R.string.magic_touch_jj02_heating_title) }
        isVisible = { it.isInitialized && isPowerOn(it) }
        onClick = { device, _ -> sendConfig(device, "heat_toggle") }
    },
    deviceCardAction {
        id = "magic_touch_level"
        icon = { R.drawable.ic_mode_heat }
        description = { _, context -> context.getString(R.string.magic_touch_jj02_heat_level_title) }
        isVisible = { it.isInitialized && isPowerOn(it) }
        onClick = { device, _ -> sendConfig(device, "level_next") }
    },
    deviceCardAction {
        id = "magic_touch_timer"
        icon = { R.drawable.ic_timer }
        description = { _, context -> context.getString(R.string.magic_touch_jj02_timer_title) }
        isVisible = { it.isInitialized && isPowerOn(it) }
        onClick = { device, _ -> sendConfig(device, "timer_next") }
    },
    deviceCardAction {
        id = "magic_touch_refresh"
        icon = { R.drawable.ic_refresh }
        description = { _, context -> context.getString(R.string.refresh) }
        isVisible = { it.isInitialized && isPowerOn(it) }
        onClick = { device, _ -> sendConfig(device, "refresh") }
    },
)

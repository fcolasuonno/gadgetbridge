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
        label = { device, context ->
            val on = GBApplication.getDeviceSpecificSharedPrefs(device.address)
                .getBoolean(MagicTouchJj02Support.PREF_POWER, false)
            context.getString(if (on) R.string.on else R.string.off)
        }
        isVisible = { it.isInitialized }
        onClick = { device, _ -> sendConfig(device, "power_toggle") }
    },
    deviceCardAction {
        id = "magic_touch_mode"
        icon = { R.drawable.ic_mode_fan }
        description = { _, context -> context.getString(R.string.magic_touch_jj02_mode_title) }
        label = { device, _ ->
            when (GBApplication.getDeviceSpecificSharedPrefs(device.address)
                .getString(MagicTouchJj02Support.PREF_MODE, "?")) {
                "1" -> "Gentle"
                "2" -> "Relax"
                "3" -> "Stress Relief"
                "4" -> "Custom"
                else -> "?"
            }
        }
        isVisible = { it.isInitialized && isPowerOn(it) }
        onClick = { device, context ->
            val activity = context as? android.app.Activity
            if (activity == null) {
                sendConfig(device, "mode_next")
            } else {
                val names = context.resources.getStringArray(R.array.magic_touch_jj02_mode_entries)
                val values = context.resources.getStringArray(R.array.magic_touch_jj02_mode_values)
                val prefs = GBApplication.getDeviceSpecificSharedPrefs(device.address)
                val cur = prefs.getString(MagicTouchJj02Support.PREF_MODE, "1")
                val checked = values.indexOf(cur).takeIf { it >= 0 } ?: 0
                android.app.AlertDialog.Builder(activity)
                    .setTitle(R.string.magic_touch_jj02_mode_title)
                    .setSingleChoiceItems(names, checked) { dialog, which ->
                        val mode = values[which].toIntOrNull()
                        if (mode != null && mode in 1..4) {
                            sendConfig(device,"mode_$mode")
                        }
                        dialog.dismiss()
                    }
                    .show()
            }
        }
    },
    deviceCardAction {
        id = "magic_touch_heating"
        icon = { R.drawable.ic_mode_heat }
        description = { _, context -> context.getString(R.string.magic_touch_jj02_heating_title) }
        label = { device, context ->
            val on = GBApplication.getDeviceSpecificSharedPrefs(device.address)
                .getBoolean(MagicTouchJj02Support.PREF_HEATING, false)
            if (!on) {
                context.getString(R.string.off)
            } else {
                when (GBApplication.getDeviceSpecificSharedPrefs(device.address)
                    .getString(MagicTouchJj02Support.PREF_HEAT_LEVEL, "?")) {
                    "1" -> "On 40°C"
                    "2" -> "On 45°C"
                    else -> context.getString(R.string.on)
                }
            }
        }
        isVisible = { it.isInitialized && isPowerOn(it) }
        onClick = { device, context ->
            val activity = context as? android.app.Activity
            if (activity == null) {
                sendConfig(device, "heat_toggle")
            } else {
                val items = arrayOf(
                    context.getString(R.string.off),
                    context.getString(R.string.magic_touch_heat_low),
                    context.getString(R.string.magic_touch_heat_high),
                )
                val prefs = GBApplication.getDeviceSpecificSharedPrefs(device.address)
                val heatingOn = prefs.getBoolean(MagicTouchJj02Support.PREF_HEATING, false)
                val level = prefs.getString(MagicTouchJj02Support.PREF_HEAT_LEVEL, "1")
                val checked = when {
                    !heatingOn -> 0
                    level == "2" -> 2
                    else -> 1
                }
                android.app.AlertDialog.Builder(activity)
                    .setTitle(R.string.magic_touch_jj02_heating_title)
                    .setSingleChoiceItems(items, checked) { dialog, which ->
                        when (which) {
                            0 -> sendConfig(device,"heat_off")

                            1 -> {
                                sendConfig(device,"heat_on")
                                sendConfig(device,"level_1")
                            }

                            2 -> {
                                sendConfig(device,"heat_on")
                                sendConfig(device,"level_2")
                            }
                        }
                        dialog.dismiss()
                    }
                    .show()
            }
        }
    },
    deviceCardAction {
        id = "magic_touch_timer"
        icon = { R.drawable.ic_timer }
        description = { _, context -> context.getString(R.string.magic_touch_jj02_timer_title) }
        label = { device, _ ->
            GBApplication.getDeviceSpecificSharedPrefs(device.address)
                .getString(MagicTouchJj02Support.PREF_TIMER, "?") + " min"
        }
        isVisible = { it.isInitialized && isPowerOn(it) }
        onClick = { device, _ -> sendConfig(device, "refresh") }
    },
)

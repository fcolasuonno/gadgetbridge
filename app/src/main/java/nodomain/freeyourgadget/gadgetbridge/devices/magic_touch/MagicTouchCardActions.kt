package nodomain.freeyourgadget.gadgetbridge.devices.magic_touch

import nodomain.freeyourgadget.gadgetbridge.GBApplication
import nodomain.freeyourgadget.gadgetbridge.R
import nodomain.freeyourgadget.gadgetbridge.devices.DeviceCardAction
import nodomain.freeyourgadget.gadgetbridge.devices.deviceCardAction
import nodomain.freeyourgadget.gadgetbridge.impl.GBDevice
import nodomain.freeyourgadget.gadgetbridge.service.devices.magic_touch.MagicTouchJj02Support

private fun prefsOf(device: GBDevice) =
    GBApplication.getDeviceSpecificSharedPrefs(device.address)

private fun isPowerOn(device: GBDevice): Boolean =
    prefsOf(device).getBoolean(MagicTouchJj02Support.PREF_POWER, false)

private fun callConfig(device: GBDevice, key: String) {
    GBApplication.deviceService(device)?.onSendConfiguration(key)
}

fun magicTouchCustomActions(): List<DeviceCardAction> = listOf(
    deviceCardAction {
        id = "magic_touch_power"
        icon = { R.drawable.ic_power_settings_new }
        description = { _, context -> context.getString(R.string.magic_touch_jj02_power_title) }
        label = { device, context ->
            val on = prefsOf(device).getBoolean(MagicTouchJj02Support.PREF_POWER, false)
            context.getString(if (on) R.string.on else R.string.off)
        }
        isVisible = { it.isInitialized }
        onClick = { device, _ ->
            val cur = prefsOf(device).getBoolean(MagicTouchJj02Support.PREF_POWER, false)
            prefsOf(device).edit().putBoolean(MagicTouchJj02Support.PREF_POWER, !cur).apply()
            callConfig(device, "power")
        }
    },
    deviceCardAction {
        id = "magic_touch_mode"
        icon = { R.drawable.ic_mode_fan }
        description = { _, context -> context.getString(R.string.magic_touch_jj02_mode_title) }
        label = { device, _ ->
            when (prefsOf(device).getString(MagicTouchJj02Support.PREF_MODE, "?")) {
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
                val cur = prefsOf(device).getString(MagicTouchJj02Support.PREF_MODE, "1")?.toIntOrNull() ?: 1
                val next = if (cur >= 4) 1 else cur + 1
                prefsOf(device).edit().putString(MagicTouchJj02Support.PREF_MODE, next.toString()).apply()
                callConfig(device, "mode")
            } else {
                val names = context.resources.getStringArray(R.array.magic_touch_jj02_mode_entries)
                val values = context.resources.getStringArray(R.array.magic_touch_jj02_mode_values)
                val cur = prefsOf(device).getString(MagicTouchJj02Support.PREF_MODE, "1")
                val checked = values.indexOf(cur).takeIf { it >= 0 } ?: 0
                android.app.AlertDialog.Builder(activity)
                    .setTitle(R.string.magic_touch_jj02_mode_title)
                    .setSingleChoiceItems(names, checked) { dialog, which ->
                        prefsOf(device).edit().putString(MagicTouchJj02Support.PREF_MODE, values[which]).apply()
                        callConfig(device, "mode")
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
            val on = prefsOf(device).getBoolean(MagicTouchJj02Support.PREF_HEATING, false)
            if (!on) {
                context.getString(R.string.off)
            } else {
                when (prefsOf(device).getString(MagicTouchJj02Support.PREF_HEAT_LEVEL, "?")) {
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
                val cur = prefsOf(device).getBoolean(MagicTouchJj02Support.PREF_HEATING, false)
                prefsOf(device).edit().putBoolean(MagicTouchJj02Support.PREF_HEATING, !cur).apply()
                callConfig(device, "heat")
            } else {
                val items = arrayOf(
                    context.getString(R.string.off),
                    context.getString(R.string.magic_touch_heat_low),
                    context.getString(R.string.magic_touch_heat_high),
                )
                val prefs = prefsOf(device)
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
                            0 -> prefs.edit().putBoolean(MagicTouchJj02Support.PREF_HEATING, false).apply()
                            1 -> prefs.edit().putBoolean(MagicTouchJj02Support.PREF_HEATING, true)
                                .putString(MagicTouchJj02Support.PREF_HEAT_LEVEL, "1").apply()
                            2 -> prefs.edit().putBoolean(MagicTouchJj02Support.PREF_HEATING, true)
                                .putString(MagicTouchJj02Support.PREF_HEAT_LEVEL, "2").apply()
                        }
                        callConfig(device, "heat")
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
            prefsOf(device).getString(MagicTouchJj02Support.PREF_TIMER, "?") + " min"
        }
        isVisible = { it.isInitialized && isPowerOn(it) }
        onClick = { device, _ ->
            val presets = listOf(5, 10, 15, 20)
            val cur = prefsOf(device).getString(MagicTouchJj02Support.PREF_TIMER, "15")?.toIntOrNull() ?: 15
            val next = presets.firstOrNull { it > cur } ?: presets.first()
            prefsOf(device).edit().putString(MagicTouchJj02Support.PREF_TIMER, next.toString()).apply()
            callConfig(device, "timer")
        }
    },
    deviceCardAction {
        id = "magic_touch_refresh"
        icon = { R.drawable.ic_refresh }
        description = { _, context -> context.getString(R.string.refresh) }
        isVisible = { it.isInitialized && isPowerOn(it) }
        onClick = { device, _ -> callConfig(device, "refresh") }
    },
)

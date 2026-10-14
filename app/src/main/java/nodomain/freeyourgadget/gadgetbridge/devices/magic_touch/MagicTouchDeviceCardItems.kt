package nodomain.freeyourgadget.gadgetbridge.devices.magic_touch

import android.content.Context
import android.content.Intent
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import nodomain.freeyourgadget.gadgetbridge.GBApplication
import nodomain.freeyourgadget.gadgetbridge.R
import nodomain.freeyourgadget.gadgetbridge.devices.DeviceCardAction
import nodomain.freeyourgadget.gadgetbridge.devices.cards.ActionCardItem
import nodomain.freeyourgadget.gadgetbridge.devices.cards.DefaultDeviceCardItems
import nodomain.freeyourgadget.gadgetbridge.devices.cards.DeviceCardItem
import nodomain.freeyourgadget.gadgetbridge.impl.GBDevice
import nodomain.freeyourgadget.gadgetbridge.service.devices.magic_touch.MagicTouchJj02Support

fun magicTouchDeviceCardItems(device: GBDevice, coordinator: MagicTouchJj02Coordinator): List<DeviceCardItem> {
    val items = DefaultDeviceCardItems.build(coordinator, device).toMutableList()
    items.add(ActionCardItem(powerToggleAction(), visible = { it.isInitialized }))
    items.add(ActionCardItem(modeCycleAction(), visible = { it.isInitialized }))
    items.add(ActionCardItem(heatingToggleAction(), visible = { it.isInitialized }))
    items.add(ActionCardItem(levelCycleAction(), visible = { it.isInitialized }))
    items.add(ActionCardItem(timerCycleAction(), visible = { it.isInitialized }))
    items.add(ActionCardItem(refreshAction(), visible = { it.isInitialized }))
    return items
}

private fun prefsOf(device: GBDevice) =
    GBApplication.getDeviceSpecificSharedPrefs(device.address)

private fun sendAction(context: Context, action: String, config: (Intent) -> Unit = {}) {
    val intent = Intent(action)
    config(intent)
    LocalBroadcastManager.getInstance(context).sendBroadcast(intent)
}

private fun powerToggleAction(): DeviceCardAction = object : DeviceCardAction {
    override fun getId(): String = "magic_touch_power"
    override fun getIcon(device: GBDevice) = R.drawable.ic_power_settings_new
    override fun getDescription(device: GBDevice, context: Context): String =
        context.getString(R.string.magic_touch_jj02_power_title)

    override fun onClick(device: GBDevice, context: Context) {
        val cur = prefsOf(device).getBoolean(MagicTouchJj02Support.PREF_POWER, false)
        sendAction(context, MagicTouchJj02Support.ACTION_SET_POWER) {
            it.putExtra(MagicTouchJj02Support.EXTRA_POWER, !cur)
        }
    }
}

private fun modeCycleAction(): DeviceCardAction = object : DeviceCardAction {
    override fun getId(): String = "magic_touch_mode"
    override fun getIcon(device: GBDevice) = R.drawable.ic_mode_fan
    override fun getDescription(device: GBDevice, context: Context): String =
        context.getString(R.string.magic_touch_jj02_mode_title)

    override fun onClick(device: GBDevice, context: Context) {
        val cur = prefsOf(device).getString(MagicTouchJj02Support.PREF_MODE, "1")?.toIntOrNull() ?: 1
        val next = if (cur >= 4) 1 else cur + 1
        sendAction(context, MagicTouchJj02Support.ACTION_SET_MODE) {
            it.putExtra(MagicTouchJj02Support.EXTRA_MODE, next)
        }
    }
}

private fun heatingToggleAction(): DeviceCardAction = object : DeviceCardAction {
    override fun getId(): String = "magic_touch_heating"
    override fun getIcon(device: GBDevice) = R.drawable.ic_mode_heat
    override fun getDescription(device: GBDevice, context: Context): String =
        context.getString(R.string.magic_touch_jj02_heating_title)

    override fun onClick(device: GBDevice, context: Context) {
        val cur = prefsOf(device).getBoolean(MagicTouchJj02Support.PREF_HEATING, false)
        sendAction(context, MagicTouchJj02Support.ACTION_SET_HEATING) {
            it.putExtra(MagicTouchJj02Support.EXTRA_HEATING, !cur)
        }
    }
}

private fun levelCycleAction(): DeviceCardAction = object : DeviceCardAction {
    override fun getId(): String = "magic_touch_level"
    override fun getIcon(device: GBDevice) = R.drawable.ic_mode_heat
    override fun getDescription(device: GBDevice, context: Context): String =
        context.getString(R.string.magic_touch_jj02_heat_level_title)

    override fun onClick(device: GBDevice, context: Context) {
        val cur = prefsOf(device).getString(MagicTouchJj02Support.PREF_HEAT_LEVEL, "1")
        val next = if (cur == "1") 2 else 1
        sendAction(context, MagicTouchJj02Support.ACTION_SET_HEAT_LEVEL) {
            it.putExtra(MagicTouchJj02Support.EXTRA_HEAT_LEVEL, next)
        }
    }
}

private fun timerCycleAction(): DeviceCardAction = object : DeviceCardAction {
    override fun getId(): String = "magic_touch_timer"
    override fun getIcon(device: GBDevice) = R.drawable.ic_timer
    override fun getDescription(device: GBDevice, context: Context): String =
        context.getString(R.string.magic_touch_jj02_timer_title)

    override fun onClick(device: GBDevice, context: Context) {
        val presets = listOf(5, 10, 15, 20)
        val cur = prefsOf(device).getString(MagicTouchJj02Support.PREF_TIMER, "15")?.toIntOrNull() ?: 15
        val next = presets.firstOrNull { it > cur } ?: presets.first()
        sendAction(context, MagicTouchJj02Support.ACTION_SET_TIMER) {
            it.putExtra(MagicTouchJj02Support.EXTRA_TIMER, next)
        }
    }
}

private fun refreshAction(): DeviceCardAction = object : DeviceCardAction {
    override fun getId(): String = "magic_touch_refresh"
    override fun getIcon(device: GBDevice) = R.drawable.ic_refresh
    override fun getDescription(device: GBDevice, context: Context): String =
        context.getString(R.string.refresh)

    override fun onClick(device: GBDevice, context: Context) {
        sendAction(context, MagicTouchJj02Support.ACTION_REFRESH)
    }
}

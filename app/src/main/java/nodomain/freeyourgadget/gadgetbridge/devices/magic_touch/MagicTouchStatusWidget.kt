package nodomain.freeyourgadget.gadgetbridge.devices.magic_touch

import android.content.Context
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import nodomain.freeyourgadget.gadgetbridge.GBApplication
import nodomain.freeyourgadget.gadgetbridge.R
import nodomain.freeyourgadget.gadgetbridge.impl.GBDevice
import nodomain.freeyourgadget.gadgetbridge.service.devices.magic_touch.MagicTouchJj02Support
import nodomain.freeyourgadget.gadgetbridge.widgets.GBWidget
import nodomain.freeyourgadget.gadgetbridge.widgets.WidgetConfig
import nodomain.freeyourgadget.gadgetbridge.widgets.WidgetDataScope

/**
 * Live massager state (power/mode/heat/timer/battery) as text, mirrored from
 * the state prefs our support maintains from telemetry. Display-only; control
 * stays on the device card icons to avoid accidental taps.
 */
object MagicTouchStatusWidget : GBWidget<String> {
    override val id = "magic_touch_status"
    override val label = R.string.magic_touch_control_title
    override val icon = R.drawable.ic_power_settings_new

    override fun isSupportedBy(device: GBDevice): Boolean =
        device.deviceCoordinator is MagicTouchJj02Coordinator

    override suspend fun loadData(scope: WidgetDataScope, config: WidgetConfig): String {
        val dev = config.resolveDevices(this).firstOrNull() ?: return "?"
        val prefs = GBApplication.getDeviceSpecificSharedPrefs(dev.address)
        val power = prefs.getBoolean(MagicTouchJj02Support.PREF_POWER, false)
        val mode = when (prefs.getString(MagicTouchJj02Support.PREF_MODE, "?")) {
            "1" -> "Gentle"
            "2" -> "Relax"
            "3" -> "Stress Relief"
            "4" -> "Custom"
            else -> "?"
        }
        val heating = prefs.getBoolean(MagicTouchJj02Support.PREF_HEATING, false)
        val level = prefs.getString(MagicTouchJj02Support.PREF_HEAT_LEVEL, "?")
        val timer = prefs.getString(MagicTouchJj02Support.PREF_TIMER, "?")
        val batt = prefs.getString(MagicTouchJj02Support.PREF_BATTERY, "?")
        return "Power: ${if (power) "On" else "Off"}\n" +
            "Mode: $mode\n" +
            "Heat: ${if (heating) "On $level" else "Off"}\n" +
            "Timer: $timer min\n" +
            "Battery: $batt"
    }

    override fun createView(inflater: LayoutInflater, parent: ViewGroup): View {
        return TextView(parent.context).apply {
            setPadding(32, 32, 32, 32)
            textSize = 15f
        }
    }

    override fun bind(view: View, config: WidgetConfig, data: String) {
        (view as TextView).text = data
    }
}

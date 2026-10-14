package nodomain.freeyourgadget.gadgetbridge.devices.magic_touch

import nodomain.freeyourgadget.gadgetbridge.widgets.DeviceWidgetsProvider
import nodomain.freeyourgadget.gadgetbridge.widgets.GBWidget

object MagicTouchWidgetsProvider : DeviceWidgetsProvider {
    override fun getWidgets(): List<GBWidget<*>> = listOf(
        MagicTouchStatusWidget,
    )
}

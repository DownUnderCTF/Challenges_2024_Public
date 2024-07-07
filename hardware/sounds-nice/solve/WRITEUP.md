# Sounds Nice

Find the device on [FCCID](https://fccid.io/2AIMRMITVS26) and open internal photos.
Google chip IDs, finding `ATS2853` as a bluetooth chipset, answering question 1.

Find model number `ETK51` - this is an audio chipset, answering question 2.

Google the audio module's part number: "Everestek EV01SA". This gives a [datasheet](https://fccid.io/Z9G-EDF54/User-Manual/user-manual-4510471.pdf) with a schematic.

The coupling capacitor near the RX antenna is given by designator C16, with `9`pF of capaitance - answering question 3.

The I2C clock signal is labeled "I2C_SCL" and is connected to pin number `31` - answering question 4.

All together, `DUCTF{ATS2853_ETK51_9_31}`

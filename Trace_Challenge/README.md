# HTB Hardware Challenge – LED Matrix Reconstruction

## Overview

This challenge focuses on reverse engineering a hardware system composed of a Raspberry Pi connected to an LED matrix display.

We are provided with:
- A **Gerber file** describing the PCB layout
- A **CSV file** containing GPIO signal traces

The objective is to reconstruct the displayed output and recover the hidden flag.

---

## Hardware Analysis

<p align="center">
  <img src="images/gerber.png" width="400">
</p>
From the Gerber file, we can identify:

- The board is a **Raspberry Pi HAT**
- It implements a **Common Anode LED Matrix**
- The LEDs are arranged in an **8×8 grid**
- Rows and columns are labeled:
  - Rows: `R0 → R7`
  - Columns: `C0 → C7`

This confirms that the display uses a **multiplexed scanning architecture**.

---

## GPIO Mapping

<p align="center">
  <img src="images/gpio.jpg" width="350">
</p>

Using the Raspberry Pi GPIO header, we mapped the signals observed in the CSV:

### Row Control (R0–R7)
- GPIO12
- GPIO25
- GPIO24
- GPIO22
- GPIO27
- GPIO17
- GPIO18
- GPIO23

### Column Control (C0–C7)
- GPIO16
- GPIO5
- GPIO6
- GPIO13
- GPIO19
- GPIO26
- GPIO20
- GPIO21

---

## LED Matrix Operation

The LED matrix operates using a **common anode configuration**.

Each LED is controlled by:
- A **row line (anode)**
- A **column line (cathode)**

A LED at position `(Ri, Cj)` is activated when:
- Row `Ri` is enabled
- Column `Cj` is driven appropriately

The system uses **multiplexing**, where:
- Only one row is active at a time
- Columns define which LEDs in that row are lit
- The process repeats rapidly to create a persistent image

---

## Signal Analysis

The provided CSV file contains GPIO states over time.

Each row represents:
- A timestamp
- GPIO values (0 or 1)

Observations:
- Only one row GPIO is active at any given time
- Column GPIOs change dynamically

This confirms a **row-scanning multiplexing scheme**.

---

## Reconstruction Method

To reconstruct the displayed message, the following method was used:

1. load the CSV trace file
2. remove the timestamp column when necessary
3. convert all values to binary logic states
4. map the trace columns to matrix rows and columns
5. reconstruct the LED state for each sample
6. aggregate **8 consecutive states** to obtain a more stable frame
7. rotate the resulting matrix to match the physical board orientation

This temporal accumulation step is important because a single raw sample only represents part of the displayed image. Summing several consecutive states produces a much cleaner reconstruction, similar to the original MATLAB workflow.

---

## Implementation

The reconstruction was implemented in a separate Python script: `decode.py`.

The script performs:
- CSV parsing
- timestamp removal
- binary conversion of logic levels
- row/column matrix reconstruction
- temporal accumulation over 8 samples
- visualization of the reconstructed frames
- optional MP4 export

This mirrors the same logic used in the original MATLAB approach, while providing a reproducible Python implementation.

---

## Visualization

Once the LED states are reconstructed and accumulated, the hidden content becomes readable frame by frame.

A short animation can also be generated from the same data to reproduce the behavior of the original display.

---

## Result

Using the reconstruction method above, the hidden message can be recovered from the GPIO traces.

The exact flag is intentionally omitted from this write-up. The purpose of this document is to explain the reverse engineering methodology and reconstruction process rather than disclose the final answer directly.

---

## Conclusion

This challenge is a practical demonstration of how hardware behavior can leak meaningful information.

By combining:
- PCB inspection through the Gerber files
- GPIO trace analysis
- LED matrix reverse engineering
- temporal reconstruction of multiplexed states

it is possible to recover what was displayed by the device without access to the original firmware.

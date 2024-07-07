//! Blinks the LED on a Pico board
//!
//! This will blink an LED attached to GP25, which is the pin the Pico uses for the on-board LED.
#![no_std]
#![no_main]
use fugit::RateExtU32;

use eeprom24x::{ Eeprom24x, SlaveAddr };
use rp_pico as bsp;
use panic_halt as _;


use bsp::hal::{
    clocks::{init_clocks_and_plls, Clock},
    pac,
    sio::Sio,
    watchdog::Watchdog,
    self
};
use bsp::entry;
use hal::uart::{DataBits, StopBits, UartConfig};

#[entry]
fn main() -> ! {
    let mut pac = pac::Peripherals::take().unwrap();
    let core = pac::CorePeripherals::take().unwrap();
    let mut watchdog = Watchdog::new(pac.WATCHDOG);
    let sio = Sio::new(pac.SIO);

    // External high-speed crystal on the pico board is 12Mhz
    let external_xtal_freq_hz = 12_000_000u32;
    let clocks = init_clocks_and_plls(
        external_xtal_freq_hz,
        pac.XOSC,
        pac.CLOCKS,
        pac.PLL_SYS,
        pac.PLL_USB,
        &mut pac.RESETS,
        &mut watchdog,
    )
    .ok()
    .unwrap();

    let pins = hal::gpio::Pins::new(
        pac.IO_BANK0,
        pac.PADS_BANK0,
        sio.gpio_bank0,
        &mut pac.RESETS,
    );

    // Setup UART for communications with host
    let uart_pins = (
        pins.gpio0.into_function(),
        pins.gpio1.into_function(),
    );

    let mut uart = hal::uart::UartPeripheral::new(pac.UART0, uart_pins, &mut pac.RESETS)
        .enable(
            UartConfig::new(115200.Hz(), DataBits::Eight, None, StopBits::One),
            clocks.peripheral_clock.freq(),
        )
        .unwrap();

    let mut delay = cortex_m::delay::Delay::new(core.SYST, clocks.system_clock.freq().to_Hz());

    // i2c for eeprom
    let i2c = hal::I2C::i2c0(
        pac.I2C0,
        pins.gpio4.reconfigure(),
        pins.gpio5.reconfigure(),
        400.kHz(),
        &mut pac.RESETS,
        &clocks.peripheral_clock,
    );

    // eeprom
    let address = SlaveAddr::Alternative(true, true, true);
    let mut eeprom = Eeprom24x::new_m24x02(i2c, address);  

    loop {
        uart.write_full_blocking(b"here comes the data: \n\n");
        // data dump!
        let mut data = [0u8; 256];
        eeprom.read_data(0u32, &mut data);

        uart.write_full_blocking(&data);


        delay.delay_ms(500);

        cortex_m::asm::bkpt();
    }
}

// End of file


idf_component_register(SRCS "esp32c5_sniffer.c"
                       INCLUDE_DIRS "."
                       PRIV_REQUIRES esp_wifi esp_event esp_timer esp_ringbuf nvs_flash
                                     esp_driver_usb_serial_jtag)

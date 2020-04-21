initSidebarItems({"constant":[["ACCEPT_TEST_BACKLIGHT_ADDR_1","The start addresses for each of the fixtures in the acceptance test (universe 1). These are the backlights which are the colour changing lights far from the camera."],["ACCEPT_TEST_BACKLIGHT_ADDR_2",""],["ACCEPT_TEST_BACKLIGHT_ADDR_3",""],["ACCEPT_TEST_BACKLIGHT_ADDR_4",""],["ACCEPT_TEST_BACKLIGHT_ADDR_5",""],["ACCEPT_TEST_BACKLIGHT_ADDR_6",""],["ACCEPT_TEST_BACKLIGHT_ADDR_7",""],["ACCEPT_TEST_BACKLIGHT_ADDR_8",""],["ACCEPT_TEST_BACKLIGHT_CH_COUNT","The number of addresses taken up by the backlights in the acceptance test."],["ACCEPT_TEST_DURATION","The time the acceptance test sequence should keep cycling for."],["ACCEPT_TEST_FRONTLIGHT_ADDR_1","The start addresses for each of the fixtures in the acceptance test. Offset by the universe channel capacity as they are universe 2.  These are the frontlights which are near the camera."],["ACCEPT_TEST_FRONTLIGHT_ADDR_2",""],["ACCEPT_TEST_FRONTLIGHT_ADDR_3",""],["ACCEPT_TEST_FRONTLIGHT_CH_COUNT","The number of addresses taken up by the frontlights in the acceptance test."],["ACCEPT_TEST_UNI_1","The 2 universes used for the acceptance test. ACCEPT_TEST_UNI_1 contains the backlight fixtures and ACCEPT_TEST_UNI_2 the frontlight fixtures."],["ACCEPT_TEST_UNI_2",""],["ACTION_ALL_DATA_OPTION","User string for the all data option which sends an entire universe of data to a given address with all values set to the given value."],["ACTION_DATA_OPTION","User string for the data command to send a packet of data."],["ACTION_DATA_OVER_TIME_OPTION","User string for the send data over time command which sends data to a specific universe that varies over time."],["ACTION_FULL_DATA_OPTION","User string for the full data command to send a full universe of data."],["ACTION_IGNORE","User string to indicate that the input line should be ignored. This is mainly used for comments within the automated test input files."],["ACTION_PREVIEW_OPTION","User string for the preview command to set if preview data should be received."],["ACTION_REGISTER_OPTION","User string for the register command to register a universe for sending."],["ACTION_SLEEP_OPTION","User string for the sleep command to make the sender wait for a certain period of time."],["ACTION_SYNC_OPTION","User string for the sync command to send a synchronisation packet."],["ACTION_TERMINATE_OPTION","User string for the terminate/quit command to terminate sending on a universe or terminate the sender entirely."],["ACTION_TEST_PRESENT_OPTION","User string for the test preset command which runs on of the interoperability test presets."],["ACTION_UNICAST_OPTION","User string for the unicast data command to send a packet of data using unicast."],["ACTION_UNICAST_SYNC_OPTION","User string for the unicast syncronisation command to send a synchronisation packet over unicast."],["MOVING_CHANNEL_TEST_WAVE_OFFSET","The offset between each channel in the wave used in the test moving channel preset. The value is dimensionless and corresponds to the scale factor used on the position of the channel in the universe. E.g. 1 is the first channel after the startcode and with a scale factor of 10 it becomes 1 * 10 = 10. This is then added onto x value used for the sine wave. This allows each channel to move slightly seperately. "],["MOVING_CHANNEL_TEST_WAVE_PERIOD","The period of the wave used in the test moving channel preset. In milliseconds."],["SHAPE_DATA_SEND_PERIOD","The period between updates to the values send during the shape generation command. Default value is approximately 30 updates per second choosen fairly arbitarily to be less than the DMX refresh rate (44 fps)."],["TERMINATE_START_CODE","The start code used in termination packets."],["TEST_PRESET_ACCEPTANCE_TEST","Test preset number for acceptance test 100. "],["TEST_PRESET_DURATION","The duration of one of the preset tests.  Each preset test run for 20 seconds."],["TEST_PRESET_HIGH_DATA_RATE","The test number for the high data rate sender interoperability test (9)."],["TEST_PRESET_HIGH_DATA_RATE_UNI_COUNT","The number of universes to send on during the high data rate test preset."],["TEST_PRESET_HIGH_DATA_RATE_VARIATION_RANGE","The range of values for each universe within the high data rate test preset."],["TEST_PRESET_MOVING_CHANNELS","The test number for the moving channels sender interoperability test (7)."],["TEST_PRESET_RAPID_CHANGES","The test number for the preset rapid changes sender interoperability test (8)."],["TEST_PRESET_RAPID_CHANGE_PERIOD","The period of the square wave generated as part of this test. Measured in packets. "],["TEST_PRESET_TWO_UNIVERSE","The test preset numbers which correspond to the various preset tests described in the sender-interoperability testing document. The test number for the two universes sender interoperability test (3)."],["TEST_PRESET_TWO_UNIVERSE_UNICAST","The test number for the two universes unicast sender interoperability test (4)."],["TEST_PRESET_UPDATE_PERIOD","The minimum length of time to wait between sending data packets during the test preset tests."]],"fn":[["display_help","Displays the usage/help string to stdout."],["gen_acceptance_test_step_1","Acceptance Test. Step 1, Backlight + Front On at full."],["gen_acceptance_test_step_1_backlight_state","Acceptance Test."],["gen_acceptance_test_step_1_frontlight_state","Acceptance Test. The front-lights only use a single channel which is brightness. For step 1 this is set to full (255)."],["gen_acceptance_test_step_2","Acceptance Test. Step 2, Red"],["gen_acceptance_test_step_2_backlight_state","Acceptance Test. Apply the changes to the backlight fixtures for step 2 (set to red). Note that only the color changes so only colour channels are affected. This relies on the buffer containing the values from step 1 already."],["gen_acceptance_test_step_3","Acceptance Test. Step 3, Blue"],["gen_acceptance_test_step_3_backlight_state","Acceptance Test. Apply the changes to the backlight fixtures for step 3 (set to blue). Note that only the color changes so only colour channels are affected. This relies on the buffer containing the values from step 2 already."],["gen_acceptance_test_step_4","Acceptance test. Step 4, All Off."],["gen_acceptance_test_step_4_backlight_state","Acceptance Test. Apply the changes to the backlight fixtures for step 4 (turn off). Note that only the brightness changes so only the brightness channel is changed. This relies on the buffer containing the values from step 3 already."],["gen_acceptance_test_step_4_frontlight_state","Acceptance Test. Apply the changes to the frontlight fixtures for step 4 (turn off). Note that only the brightness changes so only the brightness channel is changed. This relies on the buffer containing the values from step 3 already."],["get_usage_str","Describes the various commands / command-line arguments avaliable and what they do. Displayed to the user if they ask for help or enter an unrecognised input. Not a const as const with format! not supported in rust."],["handle_all_data_option","Handles the user command to send a full universe of data with all the payload being the same value (with a zero startcode)."],["handle_data_option","Sends data from the given SacnSource to the multicast address for the given data universe."],["handle_data_over_time_option","Handles the user command to send data over time. This sends arbitary data that changes over time.  The specific data isn't important as this is more to show the receiver and sender are connected properly."],["handle_full_data_option","Handles the user command to send a full universe of data which starts with the data given and then is padded with 0's upto the full length."],["handle_input","Handles input from the user."],["handle_test_preset_option","Handles the user command to run one of the test presets. These test presets are used as part of the interoperability testing as described in the Interoperability Testing document."],["handle_unicast_option","Sends data from the given SacnSource to the receiver at the given destination using unicast  (or broadcast if a broadcast IP is provided)."],["main","Entry point to the demo source. Details of usage can be found in the get_usage_str function or by running the program and typing \"h\" or \"help\"."],["run_acceptance_test_demo","Runs the acceptance test sender to vision visualiser demo."],["run_test_2_universes_distinct_values","Constantly sends data packets to 2 universes with the given values. Used as part of the interoperability testing as described in the the Interoperability Testing document."],["run_test_high_data_rate","Runs the high data rate interoperability test preset. As described in more detail within the Interoperability Testing document."],["run_test_moving_channel_preset","Runs the moving channel test preset as part of the interoperability testing. As described in more detail within the Interoperability Testing document."],["run_test_rapid_changes_preset","Runs the rapid changes test preset as part of the interoperability testing. As described in more detail within the Interoperability Testing document."]],"mod":[["error","The demo itself utilises a small error-chain which wraps the errors from the sACN crate and a few standard crates."]]});
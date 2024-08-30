Ostorlab Mobile Application Security Scanner checks multiple privacy features:

**Telephony identifiers leakage**:

* The application reads the Location Area Code value.
* The application reads the Cell ID value.
* The application reads the phone's current state.
* The application reads the current location of the device.
* The application reads the type of activity on a data connection.
* The application reads the current data connection state.
* The application reads the unique device ID, i.e the IMEI for GSM and the MEID or ESN for CDMA phones.
* The application reads the software version number for the device, for example, the IMEI/SV for GSM phones.
* The application reads the phone number string for line 1, for example, the MSISDN for a GSM phone.
* The application reads the neighboring cell information of the device.
* The application reads the ISO country code equivalent of the current registered operator's MCC (Mobile Country Code).
* The application reads the numeric name (MCC+MNC) of current registered operator.
* The application reads the operator name.
* The application reads the radio technology (network type) currently in use on the device for data transmission.
* The application reads the device phone type value.
* The application reads the ISO country code equivalent for the SIM provider's country code.
* The application reads the MCC+MNC of the provider of the SIM.
* The application reads the Service Provider Name (SPN).
* The application reads the SIM's serial number.
* The application reads the constant indicating the state of the device SIM card.
* The application reads the unique subscriber ID, for example, the IMSI for a GSM phone.
* The application reads the alphabetic identifier associated with the voice mail number.
* The application reads the voice mail number.

**Location lookup**:

* The application reads location information from all available providers (WiFi, GPS etc.).

**Connection interfaces exfiltration**:

* The application reads details about the currently active data network.
* The application tries to find out if the currently active data network is metered.
* The application reads the WiFi credentials.

**Telephony services abuse**:

* The application sends SMS messages.
* The application intercepts the incoming SMS.
* The application disables incoming SMS notifications.
* The application makes phone calls.

**Audio video eavesdropping**:

* The application records audio from mobile sources.
* The application captures video from mobile sources.

**Personal information manager data leakage**:

* The application reads or edits contact data.
* The application reads the SMS inbox.
# nfc-sun-decoder
A Decoder for NXP 424 DNA SUN (Secure Unique) messages

This library makes decoding 424 DNA SUN messages easier.
While the 424 DNA chip supports having a wide variety of data on-chip, the SUN messages are often best-used for only generating the PICCData and ignoring the rest of the URL.
This allows the rest of the metadata to reside on the server.
Therefore, many convenience functions are written with this in mind.

To set up your DNA chip to only MAC the PICC data, set SDMMACInputOffset equal to SDMMacOffset.
This will cause it to MAC a zero-length string.  
Since the generated MAC session key includes the UID and the read counter, this validates these data fields.

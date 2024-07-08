# DUCTF

Initial analysis of the binary finds a MFRC522 communcating to what is assumed to be an RFID card.
Looking a little closer we might be able to understand this is DESFire by the inclusion of an AES routines in the firmware.

From here, we can find code setting the system clock to be a harmonic of the internal ring oscillator.
This is important, as we also use the `randombit` register from the oscillator.
As per the RP2040 datasheet, this compromises the security significantly of the random number generator.
We find this random number generator always outputs the same value of 0.

We then realise we have an encryption primitive.
The use of AES-CBC, where the cipher-text of the previous message (freely controlled) gets XORed with plaintext (known via randomness leak), then encrypted and returned to us in the first 16 bytes of data.

Our encryption primitive then allows us to encrypt `rand_a` again, which for simplicity, we will also use as `rand_b`.
This then allows us to pass the `rand_ap` (`p` denotes prime as DESFire documentation) check.
We can then run through another authentication sequence to get the IV for the final data block we need to return.
We then encrypt `rand_ap` with our primitive to give our final data block which we should return to get the card data (flag).

We then need to emulate the MFRC522 enough so the various checks along the way pass, and so we can transcieve data blocks.
After this, we can get the flag.

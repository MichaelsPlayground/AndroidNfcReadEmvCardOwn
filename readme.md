This is an EMV card reader that tries to read some information about the data stored on an EMV card.

It is running in a very early state and there is no guaranty that

a) the app works

b) the app DOES NOT DESTROY YOUR CARD

Why it may be dangerous to use the app ?

The app send commands to the EMV card by the select command and that could cause a damage on the card.

So better use some outdated/expired cards for your experiments with this app - don't blame me when 
your CreditCard isn't working anymore...



Source: https://stackoverflow.com/a/51338700/8166854
The format of APDUs is defined in ISO/IEC 7816-4. A typical SELECT (by AID) command looks like this:

+-----+-----+-----+-----+-----+-------------------------+-----+
| CLA | INS | P1  | P2  | Lc  | DATA                    | Le  |
+-----+-----+-----+-----+-----+-------------------------+-----+
| 00  | A4  | 04  | 00  | XX  | AID                     | 00  |
+-----+-----+-----+-----+-----+-------------------------+-----+
You could create it like this:

private byte[] selectApdu(byte[] aid) {
byte[] commandApdu = new byte[6 + aid.length];
commandApdu[0] = (byte)0x00;  // CLA
commandApdu[1] = (byte)0xA4;  // INS
commandApdu[2] = (byte)0x04;  // P1
commandApdu[3] = (byte)0x00;  // P2
commandApdu[4] = (byte)(aid.length & 0x0FF);       // Lc
System.arraycopy(aid, 0, commandApdu, 5, aid.length);
commandApdu[commandApdu.length - 1] = (byte)0x00;  // Le
return commandApdu;
}
You could then send such APDU commands to a tag/HCE device discovered through the reader-mode API:

public abstract void onTagDiscovered(Tag tag) {
IsoDep isoDep = IsoDep.get(tag);
if (isoDep != null) {
try {
isoDep.connect();
byte[] result = isoDep.transceive(selectApdu(SelectAID));
} except (IOException ex) {
} finally {
try {
isoDep.close();
} except (Exception ignored) {}
}
}
}
Share
Edit
Follow
Flag
edited Jul 14, 2018 at 15:01
answered Jul 14, 2018 at 12:53
user avatar
Michael Roland
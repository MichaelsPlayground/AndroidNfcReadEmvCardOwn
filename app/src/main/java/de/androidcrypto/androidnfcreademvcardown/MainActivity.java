package de.androidcrypto.androidnfcreademvcardown;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.nfc.tech.NfcA;
import android.os.Bundle;
import android.os.Vibrator;
import android.widget.TextView;

import java.io.IOException;
import java.util.Arrays;

public class MainActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    TextView nfcaContent;
    private NfcAdapter mNfcAdapter;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        nfcaContent = findViewById(R.id.tvNfcaContent);

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);
    }

    @Override
    protected void onResume() {
        super.onResume();

        if (mNfcAdapter != null) {
            Bundle options = new Bundle();
            // Work around for some broken Nfc firmware implementations that poll the card too fast
            options.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 250);

            // Enable ReaderMode for all types of card and disable platform sounds
            // the option NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK is NOT set
            // to get the data of the tag afer reading
            mNfcAdapter.enableReaderMode(this,
                    this,
                    NfcAdapter.FLAG_READER_NFC_A |
                            NfcAdapter.FLAG_READER_NFC_B |
                            NfcAdapter.FLAG_READER_NFC_F |
                            NfcAdapter.FLAG_READER_NFC_V |
                            NfcAdapter.FLAG_READER_NFC_BARCODE |
                            NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS,
                    options);
        }

    }

    @Override
    protected void onPause() {
        super.onPause();
        if (mNfcAdapter != null)
            mNfcAdapter.disableReaderMode(this);
    }

    // This method is run in another thread when a card is discovered
    // !!!! This method cannot cannot direct interact with the UI Thread
    // Use `runOnUiThread` method to change the UI from this method
    @Override
    public void onTagDiscovered(Tag tag) {
        // Read and or write to Tag here to the appropriate Tag Technology type class
        // in this example the card should be an Ndef Technology Type

        // clear the datafields
        //clearEncryptionData();

        System.out.println("NFCA discovered");

        // NfcA nfca = null; // changed to IsoDep
        IsoDep isoDep = null;

        // Whole process is put into a big try-catch trying to catch the transceive's IOException
        try {

            isoDep = IsoDep.get(tag);
            if (isoDep != null) {
                Vibrator v = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
                v.vibrate(200);
            }

            isoDep.connect();
            byte[] response;
            String idContentString = "Content of ISODEP tag";

            // first get historical bytes
            response = isoDep.getHistoricalBytes();
            idContentString = idContentString + "\n" + "historical data length: " + response.length;
            idContentString = idContentString + "\n" + "Data: " + bytesToHex(response);




/*
            nfca = NfcA.get(tag);
            if (nfca != null) {
                Vibrator v = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
                v.vibrate(200);
            }

            nfca.connect();
            byte[] response;
            String nfcaContentString = "Content of NFCA tag";

            // first get sak
            short sakData = nfca.getSak();
            nfcaContentString = nfcaContentString + "\n" + "read SAK";
            nfcaContentString = nfcaContentString + "\n" + "sakData: " + shortToHex(sakData);

            // then check atqa
            byte[] atqaData = nfca.getAtqa();
            nfcaContentString = nfcaContentString + "\n" + "read ATQA";
            nfcaContentString = nfcaContentString + "\n" + "atqaData: " + bytesToHex(atqaData);

            int responseLength;
            // now testing SELECT the MasterCard application by its AID
            nfcaContentString = nfcaContentString + "\n" + "r: " + bytesToHex(hexStringToByteArray("00A4040007A000000004101000"));
            System.out.println(nfcaContentString);
*/

/*
private static readonly string MASTERCARD_AID = "A0000000041010";
// ISO-DEP command HEADER for selecting an AID.
// Format: [Class | Instruction | Parameter 1 | Parameter 2]
private static readonly string SELECT_APDU_HEADER = "00A40400";
// "OK" status word sent in response to SELECT AID command (0x9000)
private static readonly byte[] SELECT_OK_SW = { (byte)0x90, (byte)0x00 };
 */
            // wichtig: LÄNGE der MASTERCARD-ID = 7 -> 07
             //                                                  "00A40400A000000004101000"
            response = isoDep.transceive(hexStringToByteArray( "00A4040007A000000004101000"));
            //response = isoDep.Transceive(hexStringToByteArray("00A404007A000000004101000"));
            idContentString = idContentString + "\n" + "response to Mastercard AID";
            idContentString = idContentString + "\n" + "response length: " + response.length;
            idContentString = idContentString + "\n" + "response: " + bytesToHex(response);
            idContentString = idContentString + "\n" + "d:" + new String((response));

            // now the same using selectApdu
            String MasterCardAID =  "A0000000041010";
            String MaestroCardAID = "A0000000043060";
            String MShortCardAID =  "A000000004";
            String VisaCardAID = "A0000000031010"; // not tested yet
            //byte[] command = selectApdu(hexStringToByteArray(MasterCardAID));
            //byte[] command = selectApdu(hexStringToByteArray(MaestroCardAID));
            byte[] command = selectApdu(hexStringToByteArray(MShortCardAID));
            //byte[] command = selectApdu(hexStringToByteArray(VisaCardAID));
            response = isoDep.transceive(command);
            //response = isoDep.Transceive(hexStringToByteArray("00A404007A000000004101000"));
            //idContentString = idContentString + "\n" + "response to MasterCard AID with selectApdu";
            //idContentString = idContentString + "\n" + "response to MaestroCard AID with selectApdu";
            idContentString = idContentString + "\n" + "response to VisaCard AID with selectApdu";
            idContentString = idContentString + "\n" + "response length: " + response.length;
            idContentString = idContentString + "\n" + "response: " + bytesToHex(response);
            idContentString = idContentString + "\n" + "d:" + new String((response));
            // see this online decoder to get the content:
            // https://emvlab.org/tlvutils/
            System.out.println("response to VisaCard AID with selectApdu");
            System.out.println(bytesToHex(response));
            System.out.println("********* END **********");
            // visa debit hvb white
            // 6f5a8407a0000000031010a54f500e48564220566973612044656269748701015f2d086465656e667269749f38189f66049f02069f03069f1a0295055f2a029a039c019f3704bf0c139f5a0531097802769f0a0800010501000000009000
            /* structure:
6F File Control Information (FCI) Template
 	84 Dedicated File (DF) Name
 	 	A0000000031010
 	A5 File Control Information (FCI) Proprietary Template
 	 	50 Application Label
 	 	 	H V B V i s a D e b i t
 	 	87 Application Priority Indicator
 	 	 	01
 	 	5F2D Language Preference
 	 	 	d e e n f r i t
 	 	9F38 Processing Options Data Object List (PDOL)
 	 	 	9F66049F02069F03069F1A0295055F2A029A039C019F3704
 	 	BF0C File Control Information (FCI) Issuer Discretionary Data
 	 	 	9F5A Unknown tag
 	 	 	 	3109780276
 	 	 	9F0A Unknown tag
 	 	 	 	0001050100000000
90 Issuer Public Key Certificate
             */
            // aab mastercard debit
            // 6f528407a0000000041010a54750104465626974204d6173746572436172649f12104465626974204d6173746572436172648701019f1101015f2d046465656ebf0c119f0a04000101019f6e07028000003030009000
/*
6F File Control Information (FCI) Template
 	84 Dedicated File (DF) Name
 	 	A0000000041010
 	A5 File Control Information (FCI) Proprietary Template
 	 	50 Application Label
 	 	 	D e b i t M a s t e r C a r d
 	 	9F12 Application Preferred Name
 	 	 	D e b i t M a s t e r C a r d
 	 	87 Application Priority Indicator
 	 	 	01
 	 	9F11 Issuer Code Table Index
 	 	 	01
 	 	5F2D Language Preference
 	 	 	d e e n
 	 	BF0C File Control Information (FCI) Issuer Discretionary Data
 	 	 	9F0A Unknown tag
 	 	 	 	00010101
 	 	 	9F6E Unknown tag
 	 	 	 	02800000303000
90 Issuer Public Key Certificate
 */
/* tag excempt from https://emvlab.org/emvtags/all/
5A	Application Primary Account Number (PAN)	Valid cardholder account number
94	Application File Locator (AFL)	Indicates the location (SFI, range of records) of the AEFs related to a given application
4F	Application Identifier (AID) – card	Identifies the application as described in ISO/IEC 7816-5
50	Application Label	Mnemonic associated with the AID according to ISO/IEC 7816-5
5F20	Cardholder Name	Indicates cardholder name according to ISO 7813
9F0B	Cardholder Name Extended	Indicates the whole cardholder name when greater than 26 characters using the same coding convention as in ISO 7813
8E	Cardholder Verification Method (CVM) List	Identifies a method of verification of the cardholder supported by the application
83	Command Template	Identifies the data field of a command message
84	Dedicated File (DF) Name	Identifies the name of the DF as described in ISO/IEC 7816-4
9D	Directory Definition File (DDF) Name	Identifies the name of a DF associated with a directory
A5	File Control Information (FCI) Proprietary Template	Identifies the data object proprietary to this specification in the FCI template according to ISO/IEC 7816-4
6F	File Control Information (FCI) Template	Identifies the FCI template according to ISO/IEC 7816-4
9F1E	Interface Device (IFD) Serial Number	Unique and permanent serial number assigned to the IFD by the manufacturer
9F13	Last Online Application Transaction Counter (ATC) Register	ATC value of the last transaction that went online
9F17	Personal Identification Number (PIN) Try Counter	Number of PIN tries remaining
9F38	Processing Options Data Object List (PDOL)	Contains a list of terminal resident data objects (tags and lengths) needed by the ICC in processing the GET PROCESSING OPTIONS command
9F1F	Track 1 Discretionary Data	Discretionary part of track 1 according to ISO/IEC 7813
9F20	Track 2 Discretionary Data	Discretionary part of track 2 according to ISO/IEC 7813
57	Track 2 Equivalent Data	Contains the data elements of track 2 according to ISO/IEC 7813, excluding start sentinel, end sentinel, and Longitudinal Redundancy Check (LRC), as follows: Primary Account Number (n, var. up to 19) Field Separator (Hex 'D') (b) Expiration Date (YYMM) (n 4) Service Code (n 3) Discretionary Data (defined by individual payment systems) (n, var.) Pad with one Hex 'F' if needed to ensure whole bytes (b)
9A	Transaction Date	Local date that the transaction was authorised
99	Transaction Personal Identification Number (PIN) Data	Data entered by the cardholder for the purpose of the PIN verification
 */
// https://www.openscdp.org/scripts/tutorial/emv/
// https://www.openscdp.org/scripts/tutorial/emv/reademv.html
// https://www.openscdp.org/scripts/tutorial/emv/applicationselection.html
// https://stackoverflow.com/questions/37394699/unable-to-identify-afl-on-a-smart-card/37396191#37396191
// https://stackoverflow.com/questions/38998065/how-to-read-response-from-a-credit-card-over-nfc
// https://stackoverflow.com/a/37396191/2425802
// https://stackoverflow.com/questions/283251/how-do-i-read-the-pan-from-an-emv-smartcard-from-java
// https://stackoverflow.com/questions/15059580/reading-emv-card-using-ppse-and-not-pse



            // brute force to read data
            byte[] result;
            //for (int sfi = 1; sfi < 10; ++sfi ) {
            for (int sfi = 1; sfi <= 31; ++sfi ) {
                //for (int record = 1; record < 10; ++record) {
                for (int record = 1; record <= 16; ++record) {
                    byte[] cmd = hexStringToByteArray("00B2000400");
                    cmd[2] = (byte)(record & 0x0FF);
                    cmd[3] |= (byte)((sfi << 3) & 0x0F8);
                    result = isoDep.transceive(cmd);
                    if ((result != null) && (result.length >=2)) {
                        idContentString = idContentString + "\n" + "result: " + bytesToHex(result);
                        if ((result[result.length - 2] == (byte)0x90) && (result[result.length - 1] == (byte)0x00)) {
                            // file exists and contains data
                            byte[] data = Arrays.copyOf(result, result.length - 2);
                            // TODO: parse data
                            idContentString = idContentString + "\n" + "bf data length: " + data.length;
                            idContentString = idContentString + "\n" + "sfi: " + sfi + " rec: " + record;
                            idContentString = idContentString + "\n" + "bf d: " + bytesToHex(data);
                            idContentString = idContentString + "\n" + "bf d: " + new String(data);
                        }
                    }
                }
            }





            byte[] getProcessingOptions={(byte)0x80,(byte)0xA8,(byte)0x00,(byte)0x00,(byte)0x02,(byte)0x83,(byte)0x00,(byte)0x00};

            response = isoDep.transceive(getProcessingOptions);
            //response = isoDep.Transceive(hexStringToByteArray("00A404007A000000004101000"));
            //idContentString = idContentString + "\n" + "response to MasterCard AID with selectApdu";
            idContentString = idContentString + "\n" + "response to ProcessingOptions";
            idContentString = idContentString + "\n" + "response length: " + response.length;
            idContentString = idContentString + "\n" + "response: " + bytesToHex(response);
            idContentString = idContentString + "\n" + "d:" + new String((response));

            byte[] readRecord={(byte)0x00,(byte)0xB2,(byte)0x02,(byte)0x0C,(byte)0x00};
            response = isoDep.transceive(readRecord);
            //response = isoDep.Transceive(hexStringToByteArray("00A404007A000000004101000"));
            //idContentString = idContentString + "\n" + "response to MasterCard AID with selectApdu";
            idContentString = idContentString + "\n" + "response to readRecord";
            idContentString = idContentString + "\n" + "response length: " + response.length;
            idContentString = idContentString + "\n" + "response: " + bytesToHex(response);
            idContentString = idContentString + "\n" + "d:" + new String((response));





            String finalIdContentString = idContentString;
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    //UI related things, not important for NFC
                    nfcaContent.setText(finalIdContentString);
                }
            });

            try {
                isoDep.close();
            } catch (IOException e) {
                e.printStackTrace();
            }

        } catch (IOException e) {
            //Trying to catch any ioexception that may be thrown
            e.printStackTrace();
        } catch (Exception e) {
            //Trying to catch any exception that may be thrown
            e.printStackTrace();
        }

    }

    @Override
    public void onPointerCaptureChanged(boolean hasCapture) {
        super.onPointerCaptureChanged(hasCapture);
    }

    // https://stackoverflow.com/a/51338700/8166854
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


    // source: https://stackoverflow.com/a/37047375/8166854 May 5, 2016 at 9:46
    // user Michael Roland
    boolean testCommand(NfcA nfcA, byte[] command) throws IOException {
        final boolean leaveConnected = nfcA.isConnected();

        boolean commandAvailable = false;

        if (!leaveConnected) {
            nfcA.connect();
        }

        try {
            byte[] result = nfcA.transceive(command);
            if ((result != null) &&
                    (result.length > 0) &&
                    !((result.length == 1) && ((result[0] & 0x00A) == 0x000))) {
                // some response received and response is not a NACK response
                commandAvailable = true;

                // You might also want to check if you received a response
                // that is plausible for the specific command before you
                // assume that the command is actualy available and what
                // you expected...
            }
        } catch (IOException e) {
            // IOException (including TagLostException) could indicate that
            // either the tag is no longer in range or that the command is
            // not supported by the tag
        }

        try {
            nfcA.close();
        } catch (Exception e) {}

        if (leaveConnected) {
            nfcA.connect();
        }

        return commandAvailable;
    }

    public static String shortToHex(short data) {
        return Integer.toHexString(data & 0xffff);
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuffer result = new StringBuffer();
        for (byte b : bytes) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Build APDU for SELECT AID command. This command indicates which service a reader is
     * interested in communicating with. See ISO 7816-4.
     *
     * @param aid Application ID (AID) to select
     * @return APDU for SELECT AID command
     */
    /*
    public static byte[] BuildSelectApdu(String aid)
    {
        // Format: [CLASS | INSTRUCTION | PARAMETER 1 | PARAMETER 2 | LENGTH | DATA]
        return hexStringToByteArray(SELECT_APDU_HEADER + (aid.length() / 2).ToString("X2") + aid);
    }
*/
}
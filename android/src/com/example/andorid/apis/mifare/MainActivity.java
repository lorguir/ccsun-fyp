/*
 * Based on the tutorial written by Domnic <http://mifareclassicdetectiononandroid.blogspot.com/2011/04/reading-mifare-classic-1k-from-android.html>
 */

package com.example.andorid.apis.mifare;

import java.io.IOException;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.PendingIntent;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.IntentFilter.MalformedMimeTypeException;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.MifareClassic;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

public class MainActivity extends Activity{
	// UI Elements
	private static TextView block_0_Data;
//	private static TextView block_1_Data;
//	private static TextView status_Data;
	// NFC parts
	private static NfcAdapter mAdapter;
	private static PendingIntent mPendingIntent;
	private static IntentFilter[] mFilters;
	private static String[][] mTechLists;
	// Hex help
	private static final byte[] HEX_CHAR_TABLE = { (byte) '0', (byte) '1',
			(byte) '2', (byte) '3', (byte) '4', (byte) '5', (byte) '6',
			(byte) '7', (byte) '8', (byte) '9', (byte) 'A', (byte) 'B',
			(byte) 'C', (byte) 'D', (byte) 'E', (byte) 'F' };
	// Just for alerts

	private static final int AUTH = 1;
	private static final int EMPTY_BLOCK_0 = 2;
	private static final int EMPTY_BLOCK_1 = 3;
	private static final int NETWORK = 4;
	private static final String TAG = "purchtagscanact";

	/** Called when the activity is first created. */
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.main);

		block_0_Data = (TextView) findViewById(R.id.output);
//		block_1_Data = (TextView) findViewById(R.id.block_1_data);
//		status_Data = (TextView) findViewById(R.id.status_data);

		// Capture Purchase button from layout
		//Button scanBut = (Button) findViewById(R.id.btnClear);
		// Register the onClick listener with the implementation above
		//scanBut.setOnClickListener(this);

//		// Register the onClick listener with the implementation above
//		scanBut.setOnClickListener(this);

		mAdapter = NfcAdapter.getDefaultAdapter(this);
		// Create a generic PendingIntent that will be deliver to this activity.
		// The NFC stack
		// will fill in the intent with the details of the discovered tag before
		// delivering to
		// this activity.
		mPendingIntent = PendingIntent.getActivity(this, 0, new Intent(this,
				getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);
		// Setup an intent filter for all MIME based dispatches
		IntentFilter ndef = new IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED);

		try {
			ndef.addDataType("*/*");
		} catch (MalformedMimeTypeException e) {
			throw new RuntimeException("fail", e);
		}
		mFilters = new IntentFilter[] { ndef, };

		// Setup a tech list for all NfcF tags
		mTechLists = new String[][] { new String[] { MifareClassic.class
				.getName() } };

		Intent intent = getIntent();
		resolveIntent(intent);

	}

	void resolveIntent(Intent intent) {
		// Parse the intent
		String action = intent.getAction();
		if (NfcAdapter.ACTION_TECH_DISCOVERED.equals(action)) {
			// status_Data.setText("Discovered tag with intent: " + intent);
			Tag tagFromIntent = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
			MifareClassic mfc = MifareClassic.get(tagFromIntent);
			byte[] data;
			try {
				mfc.connect();
				boolean auth = false;
				String cardData = null;
				String formattedcardData = null;
				//status_Data.setText("Authenticating the Tag..");
				// Authenticating and reading Block 0 /Sector 1
				auth = mfc.authenticateSectorWithKeyA(1,
						MifareClassic.KEY_NFC_FORUM );
						
				/*
				 * extract the balance amount.
				 * extraction is done by specifying the location.
				 * (10, 15) is where balance amount is stored.
				 */
				if (auth) {
					data = mfc.readBlock(4);
					cardData = convertHexToString(getHexString(data, data.length));
					formattedcardData = cardData.substring(10,15);
					
					if (cardData != null) {						
						block_0_Data.setText(formattedcardData);
					} else {
						showAlert(EMPTY_BLOCK_0);
					}
					
				} else {
					showAlert(AUTH);
				}

			} catch (IOException e) {
				Log.e(TAG, e.getLocalizedMessage());
				showAlert(NETWORK);
			}
		} else {
			//status_Data.setText("Online + Scan a tag");
		}
	}

	private void showAlert(int alertCase) {
		// prepare the alert box
		AlertDialog.Builder alertbox = new AlertDialog.Builder(this);
		switch (alertCase) {

		case AUTH:// Card Authentication Error
			alertbox.setMessage("Invalid Card");
			break;
		case EMPTY_BLOCK_0: // Block 0 Empty
			alertbox.setMessage("Invalid Card");
			break;
		case EMPTY_BLOCK_1:// Block 1 Empty
			alertbox.setMessage("Invalid Card");
			break;
		case NETWORK: // Communication Error
			alertbox.setMessage("Cannot communicate with the card");
			break;
		}
		// set a positive/yes button and create a listener
		alertbox.setPositiveButton("OK", new DialogInterface.OnClickListener() {

			// Save the data from the UI to the database - already done
			public void onClick(DialogInterface arg0, int arg1) {
				// do nothing
			}
		});
		// display box
		alertbox.show();

	}


	public static String getHexString(byte[] raw, int len) {
		byte[] hex = new byte[2 * len];
		int index = 0;
		int pos = 0;

		for (byte b : raw) {
			if (pos >= len)
				break;

			pos++;
			int v = b & 0xFF;
			hex[index++] = HEX_CHAR_TABLE[v >>> 4];
			hex[index++] = HEX_CHAR_TABLE[v & 0xF];
		}

		return new String(hex);
	}
	
	//http://www.mkyong.com/java/how-to-convert-hex-to-ascii-in-java/
	public String convertHexToString(String hex){
		 
		  StringBuilder sb = new StringBuilder();
		  StringBuilder temp = new StringBuilder();
	 
		  //49204c6f7665204a617661 split into two characters 49, 20, 4c...
		  for( int i=0; i<hex.length()-1; i+=2 ){
	 
		      //grab the hex in pairs
		      String output = hex.substring(i, (i + 2));
		      //convert hex to decimal
		      int decimal = Integer.parseInt(output, 16);
		      //convert the decimal to character
		      sb.append((char)decimal);
	 
		      temp.append(decimal);
		  }
		  System.out.println("Decimal : " + temp.toString());
	 
		  return sb.toString();
	  }

	@Override
	public void onResume() {
		super.onResume();
		mAdapter.enableForegroundDispatch(this, mPendingIntent, mFilters,
				mTechLists);
	}

	@Override
	public void onNewIntent(Intent intent) {
		Log.i("Foreground dispatch", "Discovered tag with intent: " + intent);
		resolveIntent(intent);
		// mText.setText("Discovered tag " + ++mCount + " with intent: " +
		// intent);
	}

	@Override
	public void onPause() {
		super.onPause();
		mAdapter.disableForegroundDispatch(this);
	}
}
package com.jotish.practointerviewround;

import java.util.ArrayList;
import java.util.List;

import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import org.json.JSONException;
import org.json.JSONObject;







import android.os.AsyncTask;
import android.os.Bundle;
import android.os.CountDownTimer;
import android.app.Activity;
import android.view.Menu;
import android.widget.TextView;


public class MainActivity extends Activity {
   private ConnectionDetector cd;
   private int lag; // Lag b/w server time and system time 0 or else if no lag
   private final String SHARED_KEY="1234567"; //A key generated by User Action Let's say login activity 
   private final int LENGTH_OTP=5; //Length of OTP key
   private final int HASH_ALGORITHM=0; // Hash Algorithm to be used.0=> HmacSHA1, 1=> HmacSHA256
   private String otp_key;
   private TextView keyTextView;
   private TextView timerTextView;
   JSONParser jsonParser = new JSONParser();
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		 keyTextView = (TextView) findViewById(R.id.otpkey);
		 timerTextView = (TextView) findViewById(R.id.timertextview);
		 cd = new ConnectionDetector(getApplicationContext());
		  if (!cd.isConnectingToInternet()) {
	            // Internet Connection is not present
			    this.lag=0;
	        } 
		  else
		  {
			  new TimeSync().execute();	  
			   
		  }  
		
		 otp_key = TokenGenerator.gen(SHARED_KEY,LENGTH_OTP,HASH_ALGORITHM,lag);
	 	 keyTextView.setText(otp_key); 
	 	 long testTime = (long) (System.currentTimeMillis() / 1000L);
	 	 callTimer(60-(int)testTime%60);
	}
	
	/*Function for repetitive  calls to a timer*/
	public void callTimer(int duration)//duration in seconds
	{
		duration=duration*1000;
		new CountDownTimer(duration, 1000) {

		     public void onTick(long millisUntilFinished) {
		    	 timerTextView.setText("This will expire in : " + millisUntilFinished / 1000  + " seconds");
		     }

		     public void onFinish() {
		    	 otp_key = TokenGenerator.gen(SHARED_KEY,LENGTH_OTP,HASH_ALGORITHM,lag);
		 		keyTextView.setText(otp_key);  
		 		callTimer(60);//Recursively calling every 60 seconds
		     }
		  }.start();  
		
	}
	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.main, menu);
		return true;
	}

	
	class TimeSync extends AsyncTask<String, String, String> {
		private long currentTime1;
		private long currentTime2;
		private long server_time;
		protected void onPreExecute() {
			currentTime1= (long) System.currentTimeMillis();
		}
		
		protected String doInBackground(String... args) {
			
		    String mode = "GET_SERVER_TIME";
		    
	     
			// Building Parameters
			List<NameValuePair> paramsLogin= new ArrayList<NameValuePair>();
			paramsLogin.add(new BasicNameValuePair("mode", mode));
			
	
			// getting JSON string from URL
			JSONObject jsonLogin = jsonParser.makeHttpRequest(ConnectionDetector.URL, "GET", paramsLogin);
			
			try {
				
				int status = jsonLogin.getInt("status");
				if(status==1)
				{
					currentTime2= (long) System.currentTimeMillis();
					server_time=jsonLogin.getLong("time");
					lag=(int) ((server_time + (currentTime2-currentTime1))-currentTime2);
					
				}	
				else
				 lag=0;	
				
			}
			catch (JSONException e) {
				
			}
			
		
			return null;
		}
		
		 protected void onPostExecute(String file_url) {
			 
	        	
		 }
		}	
	
}

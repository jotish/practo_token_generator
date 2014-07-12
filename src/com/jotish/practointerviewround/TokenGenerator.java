package com.jotish.practointerviewround;

import java.lang.reflect.UndeclaredThrowableException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.TimeZone;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;


public class TokenGenerator {


	  private static byte[] hmac_sha1(String crypto, byte[] keyBytes, byte[] text)
	    {
	        try
	        {
	            Mac hmac;
	            hmac = Mac.getInstance(crypto);
	            SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
	            hmac.init(macKey);
	            return hmac.doFinal(text);
	        } catch (GeneralSecurityException gse)
	        {
	            throw new UndeclaredThrowableException(gse);
	        }
	    }
	  private static byte[] hexStr2Bytes(String hex)
	    {
	        // Adding one byte to get the right conversion
	        // values starting with "0" can be converted
	        byte[] bArray = new BigInteger("10" + hex, 16).toByteArray();

	        // Copy all the REAL bytes, not the "first"
	        byte[] ret = new byte[bArray.length - 1];
	        for (int i = 0; i < ret.length; i++)
	            ret[i] = bArray[i + 1];
	        return ret;
	    }
	  public static String gen(String key, int returnDigits, int shaType, int lag)
	    {
	        long T0 = 0;
	        long X = 60; //Interval of 60 seconds
	        long testTime = (long) ((System.currentTimeMillis() +lag) / 1000L);
	        
	        String time = "0";
	        DateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
	        df.setTimeZone(TimeZone.getTimeZone("UTC"));

	        long T = (testTime - T0) / X;
	        time = Long.toHexString(T).toUpperCase();
	        while (time.length() < 16)
	            time = "0" + time;

	        String result = null;
	        byte[] hash;

	        // Get the HEX in a Byte[]
	        byte[] msg = hexStr2Bytes(time);

	        // Adding one byte to get the right conversion
	        byte[] k = hexStr2Bytes(key);

	        String crypto;
	        if (shaType == 0)
	        {
	            crypto = "HmacSHA1";
	        }
	        else if (shaType == 1)
	        {
	            crypto = "HmacSHA256";
	        }
	        else
	        {
	            // sha 256
	            crypto = "HmacSHA512";
	        }
	        hash = hmac_sha1(crypto, k, msg);

	        // put selected bytes into result int
	        int offset = hash[hash.length - 1] & 0xf;

	        int binary = ((hash[offset] & 0x7f) << 24)
	                | ((hash[offset + 1] & 0xff) << 16)
	                | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);

	        int otp = binary % (int) (Math.pow(10, returnDigits));

	        result = Integer.toString(otp);
	        while (result.length() < returnDigits)
	        {
	            result = "0" + result;
	        }
	        return result;
	    }
}

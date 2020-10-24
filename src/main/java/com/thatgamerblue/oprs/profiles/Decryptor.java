/*
 * Copyright (C) 2020 ThatGamerBlue
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package com.thatgamerblue.oprs.profiles;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Properties;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Decryptor
{
	private static final int ITERATIONS = 100000;
	private byte[] saltBytes;
	private char[] passBytes;

	public static void main(String[] args) throws IOException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidKeySpecException
	{
		new Decryptor().run();
	}

	public void run() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException
	{
		// locate properties file
		File rlFolder = new File(System.getProperty("user.home"), ".runelite");
		File rlpProps = new File(rlFolder, "runeliteplus.properties");

		// read properties in to map
		Properties properties = new Properties();
		FileReader fr = new FileReader(rlpProps);
		properties.load(fr);
		fr.close();

		// load base64 encrypted data and salt
		String encrypted = properties.getProperty("profiles.profilesData");
		String salt = properties.getProperty("profiles.salt");

		// remove prepended ¬ from data
		if (encrypted.startsWith("¬"))
		{
			// this is the easiest way to deal with a weird 00 byte that may exist before the ¬ for some reason
			encrypted = encrypted.replaceFirst("¬", "");
		}
		System.out.println("Encrypted data: " + encrypted);
		System.out.println("Salt: " + salt);

		// decode the base64 into byte arrays
		byte[] dataBytes = base64Decode(encrypted);
		saltBytes = base64Decode(salt);

		// read the password from the terminal
		Scanner scanner = new Scanner(System.in, "UTF-8");
		System.out.print("Enter encryption password: ");
		String pwIn = scanner.nextLine();
		pwIn = pwIn.replace("\r", "").replace("\n", "");
		passBytes = pwIn.toCharArray();

		System.out.println("Password: \"" + pwIn + "\"");
		System.out.println("Str len: " + pwIn.length());
		System.out.println("Byte ary len: " + passBytes.length);

		// print the password out as chars for debugging
		StringBuilder sb = new StringBuilder();
		for (char c : passBytes)
		{
			sb.append(String.format("%04x ", (int) c));
		}
		System.out.println(sb.toString());

		// decrypt the data
		String decrypted = decryptText(dataBytes, getAesKey());

		// parse the data into easily readable formats and print to terminal
		System.out.println("\nAccounts:");
		for (String line : decrypted.split("\\n"))
		{
			String[] split = line.split(":", 3);
			if (split.length == 3)
			{
				System.out.println("Label: " + split[0] + " Username: " + split[1] + " Password: " + split[2]);
			}
			else
			{
				System.out.println("Label: " + split[0] + " Username: " + split[1]);
			}
		}
	}

	private byte[] base64Decode(String data)
	{
		return Base64.getDecoder().decode(data);
	}

	private SecretKey getAesKey() throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		KeySpec spec = new PBEKeySpec(passBytes, saltBytes, ITERATIONS, 128);
		return factory.generateSecret(spec);
	}

	private static String decryptText(byte[] enc, SecretKey aesKey) throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException
	{
		Cipher cipher = Cipher.getInstance("AES");
		SecretKeySpec sks = new SecretKeySpec(aesKey.getEncoded(), "AES");
		cipher.init(Cipher.DECRYPT_MODE, sks);
		return new String(cipher.doFinal(enc));
	}
}

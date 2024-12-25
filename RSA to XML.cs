
using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;
using System.Security;
using System.Diagnostics;
using System.ComponentModel;

namespace JavaScience
{

    public class Win32
    {

        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern IntPtr CertCreateSelfSignCertificate(
           IntPtr hProv,
           ref CERT_NAME_BLOB pSubjectIssuerBlob,
           uint dwFlagsm,
           ref CRYPT_KEY_PROV_INFO pKeyProvInfo,
           IntPtr pSignatureAlgorithm,
           IntPtr pStartTime,
           IntPtr pEndTime,
           IntPtr other);


        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern bool CertStrToName(
           uint dwCertEncodingType,
           String pszX500,
           uint dwStrType,
           IntPtr pvReserved,
           [In, Out] byte[] pbEncoded,
           ref uint pcbEncoded,
           IntPtr other);

        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern bool CertFreeCertificateContext(
           IntPtr hCertStore);

    }


    [StructLayout(LayoutKind.Sequential)]
    public struct CRYPT_KEY_PROV_INFO
    {
        [MarshalAs(UnmanagedType.LPWStr)] public String pwszContainerName;
        [MarshalAs(UnmanagedType.LPWStr)] public String pwszProvName;
        public uint dwProvType;
        public uint dwFlags;
        public uint cProvParam;
        public IntPtr rgProvParam;
        public uint dwKeySpec;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CERT_NAME_BLOB
    {
        public int cbData;
        public IntPtr pbData;
    }



    public class opensslkey
    {

        const String pemprivheader = "-----BEGIN RSA PRIVATE KEY-----";
        const String pemprivfooter = "-----END RSA PRIVATE KEY-----";
        const String pempubheader = "-----BEGIN PUBLIC KEY-----";
        const String pempubfooter = "-----END PUBLIC KEY-----";
        const String pemp8header = "-----BEGIN PRIVATE KEY-----";
        const String pemp8footer = "-----END PRIVATE KEY-----";
        const String pemp8encheader = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
        const String pemp8encfooter = "-----END ENCRYPTED PRIVATE KEY-----";

        // static byte[] pempublickey;
        // static byte[] pemprivatekey;
        // static byte[] pkcs8privatekey;
        // static byte[] pkcs8encprivatekey;

        static bool verbose = false;

        public static void NewMain(String[] args)
        {

            if (args.Length == 1)
                if (args[0].ToUpper() == "V")
                    verbose = true;

            Console.ForegroundColor = ConsoleColor.Gray;


            StreamReader sr = File.OpenText(@"C:\Users\sauda\source\repos\EpicFHIR472\Priv.pem.txt");
            String pemstr = sr.ReadToEnd().Trim();
            sr.Close();
            if (pemstr.StartsWith("-----BEGIN"))
                DecodePEMKey(pemstr);
            else
                Console.WriteLine("Error.");

        }





        // ------- Decode PEM pubic, private or pkcs8 key ----------------
        public static void DecodePEMKey(String pemstr)
        {

            byte[] pkcs8privatekey;
            byte[] pkcs8encprivatekey;


            if (pemstr.StartsWith(pemp8header) && pemstr.EndsWith(pemp8footer))
            {
                Console.WriteLine("Trying to decode and parse as PEM PKCS #8 PrivateKeyInfo ..");
                pkcs8privatekey = DecodePkcs8PrivateKey(pemstr);
                if (pkcs8privatekey != null)
                {
                    if (verbose)
                        showBytes("\nPKCS #8 PrivateKeyInfo", pkcs8privatekey);
                    //PutFileBytes("PrivateKeyInfo", pkcs8privatekey, pkcs8privatekey.Length) ;
                    RSACryptoServiceProvider rsa = DecodePrivateKeyInfo(pkcs8privatekey);
                    if (rsa != null)
                    {
                        Console.WriteLine("\nCreated an RSACryptoServiceProvider instance\n");
                        String xmlprivatekey = rsa.ToXmlString(true);
                        Console.WriteLine("\nXML RSA private key:  {0} bits\n{1}\n", rsa.KeySize, xmlprivatekey);
                    }
                    else
                        Console.WriteLine("\nFailed to create an RSACryptoServiceProvider");
                }
            }



            else
            {
                Console.WriteLine("Not a PEM public, private key or a PKCS #8");
                return;
            }
        }














        //--------   Get the binary PKCS #8 PRIVATE key   --------
        public static byte[] DecodePkcs8PrivateKey(String instr)
        {
            const String pemp8header = "-----BEGIN PRIVATE KEY-----";
            const String pemp8footer = "-----END PRIVATE KEY-----";
            String pemstr = instr.Trim();
            byte[] binkey;
            if (!pemstr.StartsWith(pemp8header) || !pemstr.EndsWith(pemp8footer))
                return null;
            StringBuilder sb = new StringBuilder(pemstr);
            sb.Replace(pemp8header, "");  //remove headers/footers, if present
            sb.Replace(pemp8footer, "");

            String pubstr = sb.ToString().Trim();   //get string after removing leading/trailing whitespace

            try
            {
                binkey = Convert.FromBase64String(pubstr);
            }
            catch (System.FormatException)
            {       //if can't b64 decode, data is not valid
                return null;
            }
            return binkey;
        }


        //------- Parses binary asn.1 PKCS #8 PrivateKeyInfo; returns RSACryptoServiceProvider ---
        public static RSACryptoServiceProvider DecodePrivateKeyInfo(byte[] pkcs8)
        {
            // encoded OID sequence for  PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
            // this byte[] includes the sequence byte and terminal encoded null 
            byte[] SeqOID = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
            byte[] seq = new byte[15];
            // ---------  Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob  ------
            MemoryStream mem = new MemoryStream(pkcs8);
            int lenstream = (int)mem.Length;
            BinaryReader binr = new BinaryReader(mem);    //wrap Memory Stream with BinaryReader for easy reading
            byte bt = 0;
            ushort twobytes = 0;

            try
            {

                twobytes = binr.ReadUInt16();
                if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                    binr.ReadByte();    //advance 1 byte
                else if (twobytes == 0x8230)
                    binr.ReadInt16();   //advance 2 bytes
                else
                    return null;


                bt = binr.ReadByte();
                if (bt != 0x02)
                    return null;

                twobytes = binr.ReadUInt16();

                if (twobytes != 0x0001)
                    return null;

                seq = binr.ReadBytes(15);       //read the Sequence OID
                if (!CompareBytearrays(seq, SeqOID))    //make sure Sequence for OID is correct
                    return null;

                bt = binr.ReadByte();
                if (bt != 0x04) //expect an Octet string 
                    return null;

                bt = binr.ReadByte();       //read next byte, or next 2 bytes is  0x81 or 0x82; otherwise bt is the byte count
                if (bt == 0x81)
                    binr.ReadByte();
                else
                 if (bt == 0x82)
                    binr.ReadUInt16();
                //------ at this stage, the remaining sequence should be the RSA private key

                byte[] rsaprivkey = binr.ReadBytes((int)(lenstream - mem.Position));
                RSACryptoServiceProvider rsacsp = DecodeRSAPrivateKey(rsaprivkey);
                return rsacsp;
            }

            catch (Exception)
            {
                return null;
            }

            finally { binr.Close(); }

        }
























        //------- Parses binary ans.1 RSA private key; returns RSACryptoServiceProvider  ---
        public static RSACryptoServiceProvider DecodeRSAPrivateKey(byte[] privkey)
        {
            byte[] MODULUS, E, D, P, Q, DP, DQ, IQ;

            // ---------  Set up stream to decode the asn.1 encoded RSA private key  ------
            MemoryStream mem = new MemoryStream(privkey);
            BinaryReader binr = new BinaryReader(mem);    //wrap Memory Stream with BinaryReader for easy reading
            byte bt = 0;
            ushort twobytes = 0;
            int elems = 0;
            try
            {
                twobytes = binr.ReadUInt16();
                if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                    binr.ReadByte();    //advance 1 byte
                else if (twobytes == 0x8230)
                    binr.ReadInt16();   //advance 2 bytes
                else
                    return null;

                twobytes = binr.ReadUInt16();
                if (twobytes != 0x0102) //version number
                    return null;
                bt = binr.ReadByte();
                if (bt != 0x00)
                    return null;


                //------  all private key components are Integer sequences ----
                elems = GetIntegerSize(binr);
                MODULUS = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                E = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                D = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                P = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                Q = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                DP = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                DQ = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                IQ = binr.ReadBytes(elems);

                Console.WriteLine("showing components ..");
                if (verbose)
                {
                    showBytes("\nModulus", MODULUS);
                    showBytes("\nExponent", E);
                    showBytes("\nD", D);
                    showBytes("\nP", P);
                    showBytes("\nQ", Q);
                    showBytes("\nDP", DP);
                    showBytes("\nDQ", DQ);
                    showBytes("\nIQ", IQ);
                }

                // ------- create RSACryptoServiceProvider instance and initialize with public key -----
                RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                RSAParameters RSAparams = new RSAParameters();
                RSAparams.Modulus = MODULUS;
                RSAparams.Exponent = E;
                RSAparams.D = D;
                RSAparams.P = P;
                RSAparams.Q = Q;
                RSAparams.DP = DP;
                RSAparams.DQ = DQ;
                RSAparams.InverseQ = IQ;
                RSA.ImportParameters(RSAparams);
                return RSA;
            }
            catch (Exception)
            {
                return null;
            }
            finally { binr.Close(); }
        }



        private static int GetIntegerSize(BinaryReader binr)
        {
            byte bt = 0;
            byte lowbyte = 0x00;
            byte highbyte = 0x00;
            int count = 0;
            bt = binr.ReadByte();
            if (bt != 0x02)     //expect integer
                return 0;
            bt = binr.ReadByte();

            if (bt == 0x81)
                count = binr.ReadByte();    // data size in next byte
            else
            if (bt == 0x82)
            {
                highbyte = binr.ReadByte(); // data size in next 2 bytes
                lowbyte = binr.ReadByte();
                byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
                count = BitConverter.ToInt32(modint, 0);
            }
            else
            {
                count = bt;     // we already have the data size
            }



            while (binr.ReadByte() == 0x00)
            {   //remove high order zeros in data
                count -= 1;
            }
            binr.BaseStream.Seek(-1, SeekOrigin.Current);       //last ReadByte wasn't a removed zero, so back up a byte
            return count;
        }











        private static IntPtr CreateUnsignedCertCntxt(String keycontainer, String provider, uint KEYSPEC, uint cspflags, String DN)
        {
            const uint AT_KEYEXCHANGE = 0x00000001;
            const uint AT_SIGNATURE = 0x00000002;
            const uint CRYPT_MACHINE_KEYSET = 0x00000020;
            const uint PROV_RSA_FULL = 0x00000001;
            const String MS_DEF_PROV = "Microsoft Base Cryptographic Provider v1.0";
            const String MS_STRONG_PROV = "Microsoft Strong Cryptographic Provider";
            const String MS_ENHANCED_PROV = "Microsoft Enhanced Cryptographic Provider v1.0";
            const uint CERT_CREATE_SELFSIGN_NO_SIGN = 1;
            const uint X509_ASN_ENCODING = 0x00000001;
            const uint CERT_X500_NAME_STR = 3;
            IntPtr hCertCntxt = IntPtr.Zero;
            byte[] encodedName = null;
            uint cbName = 0;

            if (provider != MS_DEF_PROV && provider != MS_STRONG_PROV && provider != MS_ENHANCED_PROV)
                return IntPtr.Zero;
            if (keycontainer == "")
                return IntPtr.Zero;
            if (KEYSPEC != AT_SIGNATURE && KEYSPEC != AT_KEYEXCHANGE)
                return IntPtr.Zero;
            if (cspflags != 0 && cspflags != CRYPT_MACHINE_KEYSET)   //only 0 (Current User) keyset is currently used.
                return IntPtr.Zero;
            if (DN == "")
                return IntPtr.Zero;


            if (Win32.CertStrToName(X509_ASN_ENCODING, DN, CERT_X500_NAME_STR, IntPtr.Zero, null, ref cbName, IntPtr.Zero))
            {
                encodedName = new byte[cbName];
                Win32.CertStrToName(X509_ASN_ENCODING, DN, CERT_X500_NAME_STR, IntPtr.Zero, encodedName, ref cbName, IntPtr.Zero);
            }

            CERT_NAME_BLOB subjectblob = new CERT_NAME_BLOB();
            subjectblob.pbData = Marshal.AllocHGlobal(encodedName.Length);
            Marshal.Copy(encodedName, 0, subjectblob.pbData, encodedName.Length);
            subjectblob.cbData = encodedName.Length;

            CRYPT_KEY_PROV_INFO pInfo = new CRYPT_KEY_PROV_INFO();
            pInfo.pwszContainerName = keycontainer;
            pInfo.pwszProvName = provider;
            pInfo.dwProvType = PROV_RSA_FULL;
            pInfo.dwFlags = cspflags;
            pInfo.cProvParam = 0;
            pInfo.rgProvParam = IntPtr.Zero;
            pInfo.dwKeySpec = KEYSPEC;

            hCertCntxt = Win32.CertCreateSelfSignCertificate(IntPtr.Zero, ref subjectblob, CERT_CREATE_SELFSIGN_NO_SIGN, ref pInfo, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            if (hCertCntxt == IntPtr.Zero)
                showWin32Error(Marshal.GetLastWin32Error());
            Marshal.FreeHGlobal(subjectblob.pbData);
            return hCertCntxt;
        }




        private static SecureString GetSecPswd(String prompt)
        {
            SecureString password = new SecureString();

            Console.ForegroundColor = ConsoleColor.Gray;
            Console.Write(prompt);
            Console.ForegroundColor = ConsoleColor.Magenta;

            while (true)
            {
                ConsoleKeyInfo cki = Console.ReadKey(true);
                if (cki.Key == ConsoleKey.Enter)
                {
                    Console.ForegroundColor = ConsoleColor.Gray;
                    Console.WriteLine();
                    return password;
                }
                else if (cki.Key == ConsoleKey.Backspace)
                {
                    // remove the last asterisk from the screen...
                    if (password.Length > 0)
                    {
                        Console.SetCursorPosition(Console.CursorLeft - 1, Console.CursorTop);
                        Console.Write(" ");
                        Console.SetCursorPosition(Console.CursorLeft - 1, Console.CursorTop);
                        password.RemoveAt(password.Length - 1);
                    }
                }
                else if (cki.Key == ConsoleKey.Escape)
                {
                    Console.ForegroundColor = ConsoleColor.Gray;
                    Console.WriteLine();
                    return password;
                }
                else if (Char.IsLetterOrDigit(cki.KeyChar) || Char.IsSymbol(cki.KeyChar))
                {
                    if (password.Length < 20)
                    {
                        password.AppendChar(cki.KeyChar);
                        Console.Write("*");
                    }
                    else
                    {
                        Console.Beep();
                    }
                }
                else
                {
                    Console.Beep();
                }
            }
        }





        private static bool CompareBytearrays(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                return false;
            int i = 0;
            foreach (byte c in a)
            {
                if (c != b[i])
                    return false;
                i++;
            }
            return true;
        }





        private static void showBytes(String info, byte[] data)
        {
            Console.WriteLine("{0}  [{1} bytes]", info, data.Length);
            for (int i = 1; i <= data.Length; i++)
            {
                Console.Write("{0:X2}  ", data[i - 1]);
                if (i % 16 == 0)
                    Console.WriteLine();
            }
            Console.WriteLine("\n\n");
        }


        private static byte[] GetFileBytes(String filename)
        {
            if (!File.Exists(filename))
                return null;
            Stream stream = new FileStream(filename, FileMode.Open);
            int datalen = (int)stream.Length;
            byte[] filebytes = new byte[datalen];
            stream.Seek(0, SeekOrigin.Begin);
            stream.Read(filebytes, 0, datalen);
            stream.Close();
            return filebytes;
        }





        private static void showWin32Error(int errorcode)
        {
            Win32Exception myEx = new Win32Exception(errorcode);
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("Error code:\t 0x{0:X}", myEx.ErrorCode);
            Console.WriteLine("Error message:\t {0}\n", myEx.Message);
            Console.ForegroundColor = ConsoleColor.Gray;
        }


    }
}
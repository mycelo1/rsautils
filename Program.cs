using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using Mycelo.Parsecs;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Stream;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace rsautils
{
    class Program
    {
        private const int aes_key_size = 32;
        private const int rsa_key_size = 4096;
        private const int ecc_key_size = 256;
        private const int password_length = 16;
        private const int buffer_blocks = 256;
        private static readonly byte[] salt_prefix = Encoding.ASCII.GetBytes("Salted__");
        private static readonly char file_std = '?';

        static void Main(string[] args)
        {
            ParsecsParser parser = new ParsecsParser();
            parser.AddOption('?', "help", default);

            var parser_gen = parser.AddCommand("gen", "generate PEM asymmetric public+private key pair file");
            var parser_pub = parser.AddCommand("pub", "extract a PEM public key file from key pair file");
            var parser_pwd = parser.AddCommand("pwd", "generate a random password file");
            var parser_ecc = parser.AddCommand("ecc", "generate an ECDH 'shared secret' password file");
            var parser_rsa = parser.AddCommand("rsa", "RSA-encrypt or decrypt small files (e.g. password file)");
            var parser_aes = parser.AddCommand("aes", "AES-cipher or decipher with password file");

            parser_gen.AddOption('?', "help", default);
            parser_pub.AddOption('?', "help", default);
            parser_pwd.AddOption('?', "help", default);
            parser_ecc.AddOption('?', "help", default);
            parser_rsa.AddOption('?', "help", default);
            parser_aes.AddOption('?', "help", default);

            var gen_output = parser_gen.AddString('o', "output", "output file path");
            var gen_keysize = parser_gen.AddString('l', "length", $"key bit-length (default RSA={rsa_key_size} EC={ecc_key_size})");
            var gen_choice = parser_gen.AddChoice('r', "asymmetric cryptosystem algorithm (default RSA)");
            gen_choice.AddItem('r', "rsa", "RSA (Rivest-Shamir-Adleman)");
            gen_choice.AddItem('e', "ecc", "Elliptic Curve Cryptography");

            var pub_input = parser_pub.AddString('i', "input", "input key pair file path");
            var pub_output = parser_pub.AddString('o', "output", "output public key file path");

            var pwd_output = parser_pwd.AddString('o', "output", "output BASE64 password file path");
            var pwd_length = parser_pwd.AddString('l', "length", $"password byte-length (default {password_length})");

            var sec_skey_prv = parser_ecc.AddString('y', "yours", "your ECC private key file path");
            var sec_skey_pub = parser_ecc.AddString('t', "theirs", "the other part's ECC public key file path");
            var sec_output = parser_ecc.AddString('o', "output 'shared-secret' BASE64 password file path");

            var rsa_akey_pub = parser_rsa.AddString('k', "key", "input public PEM file path");
            var rsa_akey_prv = parser_rsa.AddString('2', "pair", "input public+private pair PEM file path");
            var rsa_input = parser_rsa.AddString('i', "input", "input data file path");
            var rsa_output = parser_rsa.AddString('o', "output", "output data file path");
            var rsa_choice = parser_rsa.AddChoice('e', "operation mode (default: encrypt)");
            rsa_choice.AddItem('e', "encrypt", "RSA-encrypt with a public key");
            rsa_choice.AddItem('d', "decrypt", "RSA-decrypt with a private key or key pair");

            var aes_pwd_file = parser_aes.AddString('p', "passfile", "input BASE64 password file path");
            var aes_pwd_b64 = parser_aes.AddString('b', "base64", "input BASE64 password string");
            var aes_pwd_str = parser_aes.AddString('a', "ascii", "input plain ASCII 7-bit password string");
            var aes_input = parser_aes.AddString('i', "input", "input data file path");
            var aes_output = parser_aes.AddString('o', "output", "output data file path");
            var aes_gzip = parser_aes.AddOption('z', "gzip", "enable GZIP compression/decompression");
            var aes_choice = parser_aes.AddChoice('e', "operation mode (default: encrypt)");
            aes_choice.AddItem('e', "encrypt", "AES-256 cipher");
            aes_choice.AddItem('d', "decrypt", "AES-256 decipher");

            Console.OutputEncoding = Encoding.ASCII;

            if (parser.Parse(args))
            {
                if ((args.Length == 0) || parser['?'] || (parser.Command == parser))
                {
                    Console.WriteLine("PARAMETERS: <command> <command-options>|--help\r\n");
                    Console.WriteLine(parser.HelpTextBuilder(4, false).ToString());
                    Console.WriteLine($">>> passing a '{file_std}' char for a file name means standard input/output");
                    Console.WriteLine();
                    Console.WriteLine("RSA ENCRYPTION EXAMPLE:");
                    Console.WriteLine("$ gen --output=PRIVATE.pem");
                    Console.WriteLine("$ pub --input=PRIVATE.pem --output=PUBLIC.pem");
                    Console.WriteLine("$ pwd --output=PASSWORD.txt");
                    Console.WriteLine("$ aes --encrypt --passfile=PASSWORD.txt --input=PLAIN.txt --output=CIPHERED.bin");
                    Console.WriteLine("$ rsa --encrypt --key=PUBLIC.PEM --input=PASSWORD.txt --output=PASSWORD.bin");
                    Console.WriteLine();
                    Console.WriteLine("RSA DECRYPTION EXAMPLE:");
                    Console.WriteLine("$ rsa --decrypt --pair=PRIVATE.PEM --input=PASSWORD.bin --output=PASSWORD.txt");
                    Console.WriteLine("$ aes --decrypt --passfile=PASSWORD.txt --input=CIPHERED.bin --output=PLAIN.txt");
                }
                else if ((parser.Command != parser) && (parser.Command['?']))
                {
                    switch (parser.Command.Name)
                    {
                        case "gen":
                            Console.WriteLine($"PARAMETERS: {parser.Command.Name} --rsa|-ec --output=<private-key-file> [--length=<key-length>]\r\n");
                            Console.WriteLine(parser.Command.HelpTextBuilder(4, false).ToString());
                            Console.WriteLine("OPENSSL EQUIVALENCE:");
                            Console.WriteLine($"RSA -> $ openssl genrsa <key-length> -out <private-key-file>");
                            Console.WriteLine($"ECC -> $ openssl ecparam -name <e.g. prime256v1> -genkey -noout -out <private-key-file>");
                            break;

                        case "pub":
                            Console.WriteLine($"PARAMETERS: {parser.Command.Name} --input=<private-key-file> --output=<public-key-file>\r\n");
                            Console.WriteLine(parser.Command.HelpTextBuilder(4, false).ToString());
                            Console.WriteLine("OPENSSL EQUIVALENCE:");
                            Console.WriteLine($"$ openssl rsa -in <private-key-file> -pubout -out <public-key-file>");
                            break;

                        case "pwd":
                            Console.WriteLine($"PARAMETERS: {parser.Command.Name} --output=<password-file> [--length=<password-length>]\r\n");
                            Console.WriteLine(parser.Command.HelpTextBuilder(4, false).ToString());
                            Console.WriteLine("OPENSSL EQUIVALENCE:");
                            Console.WriteLine($"$ openssl rand -base64 <password-length> > <password-file>");
                            break;

                        case "ecc":
                            Console.WriteLine($"PARAMETERS: {parser.Command.Name} --yours=<private-key-file> --theirs=<public-key-file> --output=<password-file>\r\n");
                            Console.WriteLine(parser.Command.HelpTextBuilder(4, false).ToString());
                            Console.WriteLine("OPENSSL EQUIVALENCE:");
                            Console.WriteLine("$ openssl pkeyutl -derive -inkey <private-key_file> -peerkey <public-key-file> -out <password-file>");
                            break;

                        case "rsa":
                            Console.WriteLine($"PARAMETERS: {parser.Command.Name} --encrypt|--decrypt --key=<public-key-file>|--pair=<key-pair-file> --input=<input-file> --output=<output-file>\r\n");
                            Console.WriteLine(parser.Command.HelpTextBuilder(4, false).ToString());
                            Console.WriteLine("OPENSSL EQUIVALENCE:");
                            Console.WriteLine($"ENCRYPT -> $ openssl rsautl -encrypt -oaep -inkey <public-key-file> -pubin -in <plain-file> -out <ciphered-file>");
                            Console.WriteLine($"DECRYPT -> $ openssl rsautl -decrypt -oaep -inkey <private-key-file> -in <ciphered-file> -out <plain-file>");
                            break;

                        case "aes":
                            Console.WriteLine($"PARAMETERS: {parser.Command.Name} --encrypt|--decrypt --passfile=<password-file>|--base64=<BASE64-string>|--ascii=<ASCII-string> --input=<input-file> --output=<output-file>\r\n");
                            Console.WriteLine(parser.Command.HelpTextBuilder(4, false).ToString());
                            Console.WriteLine("OPENSSL EQUIVALENCE:");
                            Console.WriteLine($"ENCRYPT -> $ openssl aes-256-cbc -e -md sha256 -in <plain-data> -out <ciphered-data> -kfile <password-file>");
                            Console.WriteLine($"DECRYPT -> $ openssl aes-256-cbc -d -md sha256 -in <ciphered-data> -out <plain-data> -kfile <password-file>");
                            break;
                    }
                }
                else
                {
                    try
                    {
                        switch (parser.Command.Name)
                        {
                            case "gen":
                                int size;
                                if (gen_choice.Value == 'r')
                                {
                                    if (!Int32.TryParse(gen_keysize.String, out size))
                                    {
                                        size = rsa_key_size;
                                    }
                                    RSAGenKey(gen_output.String, size);
                                }
                                else
                                {
                                    if (!Int32.TryParse(gen_keysize.String, out size))
                                    {
                                        size = ecc_key_size;
                                    }
                                    ECCGenKey(gen_output.String, size);
                                }
                                break;

                            case "pub":
                                Export(pub_input.String, pub_output.String);
                                break;

                            case "pwd":
                                int length;
                                if (!Int32.TryParse(pwd_length.String, out length))
                                {
                                    length = password_length;
                                }
                                GenPassword(pwd_output.String, length);
                                break;

                            case "ecc":
                                ECCAgreement(sec_skey_pub.String, sec_skey_prv.String, sec_output.String);
                                break;

                            case "rsa":
                                if (rsa_choice.Value == 'e')
                                {
                                    RSAEncrypt(rsa_akey_pub.String, rsa_akey_prv.String, rsa_input.String, rsa_output.String);
                                }
                                else
                                {
                                    RSADecrypt(rsa_akey_prv.String, rsa_input.String, rsa_output.String);
                                }
                                break;

                            case "aes":
                                if (aes_choice.Value == 'e')
                                {
                                    AESEncrypt(aes_pwd_file.String, aes_pwd_b64.String, aes_pwd_str.String, aes_input.String, aes_output.String, aes_gzip.Switched);
                                }
                                else
                                {
                                    AESDecrypt(aes_pwd_file.String, aes_pwd_b64.String, aes_pwd_str.String, aes_input.String, aes_output.String, aes_gzip.Switched);
                                }
                                break;

                        }
                    }
                    catch (Exception e)
                    {
                        using (Stream error_stream = Console.OpenStandardError())
                        using (StreamWriter stream_writer = new StreamWriter(error_stream))
                        {
                            Exception inner = e;
                            while (inner != null)
                            {
                                stream_writer.WriteLine($"<{inner.ToString()}> {inner.Message}");
                                inner = inner.InnerException;
                            }
                        }
                    }
                }
            }
            else
            {
                using (Stream error_stream = Console.OpenStandardError())
                using (StreamWriter stream_writer = new StreamWriter(error_stream))
                {
                    stream_writer.WriteLine("wrong parameter");
                }
            }
        }

        private static void RSAGenKey(string file_output, int key_size)
        {
            using (Stream stream_output = FileOrStandardOutput(file_output))
            using (StreamWriter stream_writer = new StreamWriter(stream_output, Encoding.ASCII))
            {
                RsaKeyPairGenerator rsa_generator = new RsaKeyPairGenerator();
                rsa_generator.Init(new KeyGenerationParameters(new SecureRandom(), key_size));
                AsymmetricCipherKeyPair keyPair = rsa_generator.GenerateKeyPair();
                PemWriter pem_writer = new PemWriter(stream_writer);
                pem_writer.WriteObject(keyPair.Private);
                pem_writer.Writer.Flush();
            }
        }

        private static void ECCGenKey(string file_output, int key_size)
        {
            using (Stream stream_output = FileOrStandardOutput(file_output))
            using (StreamWriter stream_writer = new StreamWriter(stream_output, Encoding.ASCII))
            {
                ECKeyPairGenerator elc_generator = new ECKeyPairGenerator();
                elc_generator.Init(new KeyGenerationParameters(new SecureRandom(), key_size));
                AsymmetricCipherKeyPair keyPair = elc_generator.GenerateKeyPair();
                PemWriter pem_writer = new PemWriter(stream_writer);
                pem_writer.WriteObject(keyPair.Private);
                pem_writer.Writer.Flush();
            }
        }

        private static void Export(string file_input, string file_output)
        {
            using (Stream stream_input = FileOrStandardInput(file_input))
            using (Stream stream_output = FileOrStandardOutput(file_output))
            {
                AsymmetricCipherKeyPair key_pair;

                using (StreamReader stream_reader = new StreamReader(stream_input, Encoding.ASCII))
                {
                    PemReader pem_reader = new PemReader(stream_reader);
                    key_pair = (AsymmetricCipherKeyPair)pem_reader.ReadObject();
                }

                using (StreamWriter stream_writer = new StreamWriter(stream_output, Encoding.ASCII))
                {
                    PemWriter pem_writer = new PemWriter(stream_writer);
                    pem_writer.WriteObject(key_pair.Public);
                    pem_writer.Writer.Flush();
                }
            }
        }

        private static void GenPassword(string file_output, int length)
        {
            using (Stream stream_output = FileOrStandardOutput(file_output))
            {
                byte[] password;
                byte[] password_bytes = new byte[length];
                (new SecureRandom()).NextBytes(password_bytes, 0, password_bytes.Length);
                password = Encoding.ASCII.GetBytes(Convert.ToBase64String(password_bytes));
                stream_output.Write(password, 0, password.Length);
            }
        }

        private static void ECCAgreement(string file_akey_pub, string file_akey_prv, string file_output)
        {
            ECKeyParameters public_key = LoadPEMFile<ECKeyParameters>(file_akey_pub, default, false);
            ECKeyParameters private_key = LoadPEMFile<ECKeyParameters>(default, file_akey_prv, true);
            IBasicAgreement agreement = AgreementUtilities.GetBasicAgreement("ECDH");
            agreement.Init(private_key);
            BigInteger password = agreement.CalculateAgreement(public_key);

            using (Stream stream_output = FileOrStandardOutput(file_output))
            using (StreamWriter stream_writer = new StreamWriter(stream_output))
            {
                string str_password = Convert.ToBase64String(password.ToByteArray());
                stream_writer.Write(str_password);
            }
        }

        private static void RSAEncrypt(string file_akey_pub, string file_akey_prv, string file_input, string file_output)
        {
            RsaKeyParameters key_param = LoadPEMFile<RsaKeyParameters>(file_akey_pub, file_akey_prv, false);

            using (Stream stream_input = FileOrStandardInput(file_input))
            using (Stream stream_output = FileOrStandardOutput(file_output))
            using (AsymmetricCryptoStream stream_cripto = new AsymmetricCryptoStream(stream_output, new OaepEncoding(new RsaEngine(), new Sha1Digest(), new byte[0])))
            {
                stream_cripto.Init(true, key_param);
                stream_input.CopyTo(stream_cripto);
                stream_cripto.Flush();
            }
        }

        private static void RSADecrypt(string file_akey_prv, string file_input, string file_output)
        {
            RsaKeyParameters key_param = LoadPEMFile<RsaKeyParameters>(default, file_akey_prv, true);

            using (Stream stream_input = FileOrStandardInput(file_input))
            using (Stream stream_output = FileOrStandardOutput(file_output))
            using (AsymmetricCryptoStream stream_cripto = new AsymmetricCryptoStream(stream_output, new OaepEncoding(new RsaEngine(), new Sha1Digest(), new byte[0])))
            {

                stream_cripto.Init(false, key_param);
                stream_input.CopyTo(stream_cripto);
                stream_cripto.Flush();
            }
        }

        private static void AESEncrypt(string file_password, string b64_password, string str_password, string file_input, string file_output, bool compress)
        {
            byte[] password = LoadPassword(file_password, b64_password, str_password);

            using (Stream stream_input = FileOrStandardInput(file_input))
            using (Stream stream_output = FileOrStandardOutput(file_output))
            using (BufferedCryptoStream stream_cripto = new BufferedCryptoStream(stream_output, new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesFastEngine()), new Pkcs7Padding())))
            {
                using (GZipStream stream_gzip = new GZipStream(stream_cripto, CompressionMode.Compress))
                {
                    int block_size = stream_cripto.BlockSize;
                    byte[] skey;
                    byte[] salt;
                    byte[] iv;

                    salt = new byte[block_size - salt_prefix.Length];
                    (new SecureRandom()).NextBytes(salt, 0, salt.Length);
                    stream_output.Write(salt_prefix, 0, salt_prefix.Length);
                    stream_output.Write(salt, 0, salt.Length);

                    (skey, iv) = DeriveKey(password, salt, aes_key_size, block_size);
                    stream_cripto.Init(true, new ParametersWithIV(new KeyParameter(skey), iv));

                    if (compress)
                    {
                        stream_input.CopyTo(stream_gzip);
                    }
                    else
                    {
                        stream_input.CopyTo(stream_cripto);
                    }
                }
                stream_cripto.Flush();
            }
        }

        private static void AESDecrypt(string file_password, string b64_password, string str_password, string file_input, string file_output, bool uncompress)
        {
            byte[] password = LoadPassword(file_password, b64_password, str_password);

            using (Stream stream_output = FileOrStandardOutput(file_output))
            using (MemoryStream memory_stream = new MemoryStream())
            using (Stream stream_gzip = new GZipStream(memory_stream, CompressionMode.Decompress))
            {
                Stream stream_target;

                if (uncompress)
                {
                    stream_target = memory_stream;
                }
                else
                {
                    stream_target = stream_output;
                }

                using (Stream stream_input = FileOrStandardInput(file_input))
                using (BufferedCryptoStream stream_cripto = new BufferedCryptoStream(stream_target, new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesFastEngine()), new Pkcs7Padding())))
                {
                    byte[] skey;
                    byte[] salt;
                    byte[] iv;

                    byte[] array_salt_prefix = new byte[salt_prefix.Length];
                    int salt_prefix_count = 0;
                    do
                    {
                        salt_prefix_count = stream_input.Read(array_salt_prefix, salt_prefix_count, array_salt_prefix.Length - salt_prefix_count);
                    }
                    while (salt_prefix_count < array_salt_prefix.Length);

                    salt = new byte[stream_cripto.BlockSize - salt_prefix.Length];
                    int salt_count = 0;
                    do
                    {
                        salt_count = stream_input.Read(salt, salt_count, salt.Length - salt_count);
                    }
                    while (salt_count < salt.Length);

                    (skey, iv) = DeriveKey(password, salt, aes_key_size, stream_cripto.BlockSize);
                    stream_cripto.Init(false, new ParametersWithIV(new KeyParameter(skey), iv));
                    stream_input.CopyTo(stream_cripto);
                    stream_cripto.Flush();
                }

                if (uncompress)
                {
                    memory_stream.Position = 0;
                    stream_gzip.CopyTo(stream_output);
                }
            }
        }

        private static T LoadPEMFile<T>(string file_akey_pub, string file_akey_prv, bool get_private) where T : AsymmetricKeyParameter
        {
            T key_param;

            if (!String.IsNullOrWhiteSpace(file_akey_prv))
            {
                using (Stream stream_akey = FileOrStandardInput(file_akey_prv))
                using (StreamReader stream_reader = new StreamReader(stream_akey))
                {
                    PemReader pem_reader = new PemReader(stream_reader);
                    AsymmetricCipherKeyPair key_pair = (AsymmetricCipherKeyPair)pem_reader.ReadObject();

                    if (get_private)
                    {
                        key_param = (T)key_pair.Private;
                    }
                    else
                    {
                        key_param = (T)key_pair.Public;
                    }
                }
            }
            else if (!String.IsNullOrWhiteSpace(file_akey_pub))
            {
                using (Stream stream_akey = FileOrStandardInput(file_akey_pub))
                using (StreamReader stream_reader = new StreamReader(stream_akey))
                {
                    PemReader pem_reader = new PemReader(stream_reader);
                    key_param = (T)pem_reader.ReadObject();
                }
            }
            else
            {
                throw new InvalidParameterException("asymmetric encryption key not provided");
            }

            return key_param;
        }

        private static byte[] LoadPassword(string file_password, string b64_password, string str_password)
        {
            if (!String.IsNullOrWhiteSpace(file_password))
            {
                using (Stream stream_password = FileOrStandardInput(file_password))
                using (StreamReader stream_reader = new StreamReader(stream_password))
                {
                    return Convert.FromBase64String(stream_reader.ReadLine());
                }
            }
            else if (!String.IsNullOrWhiteSpace(b64_password))
            {
                return Convert.FromBase64String(b64_password);
            }
            else if (!String.IsNullOrWhiteSpace(str_password))
            {
                return Encoding.ASCII.GetBytes(str_password);
            }
            else
            {
                throw new ArgumentNullException("password");
            }
        }

        private static (byte[] key, byte[] iv) DeriveKey(byte[] password, byte[] salt, int key_size, int block_size)
        {
            var derive = new List<byte>();
            while (derive.Count < (key_size + block_size))
            {
                IDigest sha256_hash = new Sha256Digest();
                byte[] digest = new byte[sha256_hash.GetDigestSize()];
                var content = new List<byte>(derive);
                content.AddRange(password);
                content.AddRange(salt);
                sha256_hash.BlockUpdate(content.ToArray(), 0, content.Count);
                int digest_size = sha256_hash.DoFinal(digest, 0);
                derive.AddRange(digest.Take(digest_size));
            }

            return (derive.Take(key_size).ToArray(), derive.Skip(key_size).Take(block_size).ToArray());
        }

        private static Stream FileOrStandardInput(string file_name)
        {
            if (file_name == file_std.ToString())
            {
                return Console.OpenStandardInput();
            }
            else
            {
                return new FileStream(file_name, FileMode.Open, FileAccess.Read, FileShare.None);
            }
        }

        private static Stream FileOrStandardOutput(string file_name)
        {
            if (file_name == file_std.ToString())
            {
                return Console.OpenStandardOutput();
            }
            else
            {
                return new FileStream(file_name, FileMode.Create, FileAccess.Write, FileShare.None);
            }
        }
    }
}

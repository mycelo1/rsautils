using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using Mycelo.Parsecs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Stream;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace rsautils
{
    class Program
    {
        private const int aes_key_size = 32;
        private const int password_size = 16;
        private const int buffer_blocks = 256;
        private static readonly byte[] salt_prefix = Encoding.ASCII.GetBytes("Salted__");

        static void Main(string[] args)
        {
            ParsecsParser parser = new ParsecsParser();
            parser.AddOption('?', "help", default);
            var parser_gen = parser.AddCommand("gen", "generate PEM asymmetric public+private key pair file");
            var parser_pub = parser.AddCommand("pub", "extract a PEM public key file from key pair file");
            var parser_enc = parser.AddCommand("enc", "encrypt with public key");
            var parser_dec = parser.AddCommand("dec", "decrypt with private key");

            parser_gen.AddOption('?', "help", default);
            parser_pub.AddOption('?', "help", default);
            parser_enc.AddOption('?', "help", default);
            parser_dec.AddOption('?', "help", default);

            var gen_output = parser_gen.AddString('o', "output", "output file (standard output if ommited)");
            var gen_keysize = parser_gen.AddString('s', "size", "key size (default 4096)");

            var pub_input = parser_pub.AddString('i', "input", "input file (standard input if ommited)");
            var pub_output = parser_pub.AddString('o', "output", "output file (standard output if ommited)");

            var enc_akey_pub = parser_enc.AddString('k', "key", "input public PEM asymmetric key file");
            var enc_akey_prv = parser_enc.AddString('2', "pair", "input public+private PEM asymmetric key pair file");
            var enc_input = parser_enc.AddString('i', "input", "input plain file (standard input if ommited)");
            var enc_output = parser_enc.AddString('o', "output", "output AES ciphered file (standard output if ommited)");
            var enc_password = parser_enc.AddString('p', "password", "output RSA encrypted password file");
            var enc_gzip = parser_enc.AddOption('z', "gzip", "compress plain data with GZIP before encryption");

            var dec_akey_prv = parser_dec.AddString('k', "key", "input private PEM asymmetric key file");
            var dec_input = parser_dec.AddString('i', "input", "input AES ciphered file (standard input if ommited)");
            var dec_output = parser_dec.AddString('o', "output", "output plain file (standard output if ommited)");
            var dec_password = parser_dec.AddString('p', "password", "input RSA encrypted password file");
            var dec_gzip = parser_dec.AddOption('z', "gzip", "uncompress plain data with GZIP after decryption");

            Console.OutputEncoding = Encoding.ASCII;

            if (parser.Parse(args))
            {
                if ((args.Length == 0) || parser['?'] || (parser.Command == parser))
                {
                    Console.WriteLine("RSAUTILS <command> <command-options>|--help\r\n");
                    Console.WriteLine(parser.HelpTextBuilder(4, false).ToString());
                }
                else if ((parser.Command != parser) && (parser.Command['?']))
                {
                    switch (parser.Command.Name)
                    {
                        case "gen":
                            Console.WriteLine($"RSAUTILS {parser.Command.Name} [--output=<private-key-file>] [--size=<key-size>]\r\n");
                            Console.WriteLine(parser.Command.HelpTextBuilder(4, false).ToString());
                            Console.WriteLine("OPENSSL EQUIVALENCE:");
                            Console.WriteLine($"$ openssl genrsa <key-size> > <private-key-file>");
                            break;

                        case "pub":
                            Console.WriteLine($"RSAUTILS {parser.Command.Name} [--input=<private-key-file>] [--output=<public-key-file>]\r\n");
                            Console.WriteLine(parser.Command.HelpTextBuilder(4, false).ToString());
                            Console.WriteLine("OPENSSL EQUIVALENCE:");
                            Console.WriteLine($"$ openssl rsa -in <private-key-file> -pubout -out <public-key-file>");
                            break;

                        case "enc":
                            Console.WriteLine($"RSAUTILS {parser.Command.Name} --key=<public-key-file>|--pair=<key-pair-file> [--input=<plain-data-file>] [--output=<ciphered-data-file>] [--password=<password-file>]\r\n");
                            Console.WriteLine(parser.Command.HelpTextBuilder(4, false).ToString());
                            Console.WriteLine("OPENSSL EQUIVALENCE:");
                            Console.WriteLine($"$ openssl rand -base64 {password_size} > <plain-pwd-file>");
                            Console.WriteLine($"$ openssl aes-256-cbc -e -md sha256 -in <plain-data> -out <ciphered-data> -kfile <plain-pwd-file>");
                            Console.WriteLine($"$ openssl rsautl -encrypt -oaep -inkey <public-key-file> -pubin -in <plain-pwd-file> -out <ciphered-pwd-file>");
                            break;

                        case "dec":
                            Console.WriteLine($"RSAUTILS {parser.Command.Name} --key=<private-key-file> [--input=<ciphered-data-file>] [--output=<plain-data-file>] [--password=<password-file>]\r\n");
                            Console.WriteLine(parser.Command.HelpTextBuilder(4, false).ToString());
                            Console.WriteLine("OPENSSL EQUIVALENCE:");
                            Console.WriteLine($"$ openssl rsautl -decrypt -oaep -inkey <private-key-file> -in <ciphered-pwd-file> -out <plain-pwd-file>");
                            Console.WriteLine($"$ openssl aes-256-cbc -d -md sha256 -in <ciphered-data> -out <plain-data> -kfile <plain-pwd-file>");
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
                                int key_size;
                                if (!Int32.TryParse(gen_keysize.String, out key_size))
                                {
                                    key_size = 4096;
                                }
                                Generate(gen_output.String, key_size);
                                break;

                            case "pub":
                                Export(pub_input.String, pub_output.String);
                                break;

                            case "enc":
                                Encrypt(enc_akey_pub.String, enc_akey_prv.String, enc_input.String, enc_output.String, enc_password.String, enc_gzip.Switched);
                                break;

                            case "dec":
                                Decrypt(dec_akey_prv.String, dec_password.String, dec_input.String, dec_output.String, dec_gzip.Switched);
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
                                stream_writer.WriteLine(inner.Message);
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

        private static void Generate(string file_output, int key_size)
        {
            using (Stream stream_output = FileOrStandardOutput(file_output))
            using (StreamWriter stream_writer = new StreamWriter(stream_output, Encoding.ASCII))
            {
                RsaKeyPairGenerator rsaKeyPairGnr = new RsaKeyPairGenerator();
                rsaKeyPairGnr.Init(new KeyGenerationParameters(new SecureRandom(), key_size));
                AsymmetricCipherKeyPair keyPair = rsaKeyPairGnr.GenerateKeyPair();
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

        private static void Encrypt(string file_akey_pub, string file_akey_prv, string file_input, string file_output, string file_password, bool compress)
        {
            RsaKeyParameters key_param;
            string var_file_password;
            byte[] password;
            byte[] skey;
            byte[] salt;
            byte[] iv;

            if (String.IsNullOrWhiteSpace(file_password))
            {
                var_file_password = file_output + ".pwd";
            }
            else
            {
                var_file_password = file_password;
            }

            if (!String.IsNullOrWhiteSpace(file_akey_prv))
            {
                using (StreamReader stream_akey = File.OpenText(file_akey_prv))
                {
                    PemReader pem_reader = new PemReader(stream_akey);
                    AsymmetricCipherKeyPair key_pair = (AsymmetricCipherKeyPair)pem_reader.ReadObject();
                    key_param = (RsaKeyParameters)key_pair.Public;
                }
            }
            else if (!String.IsNullOrWhiteSpace(file_akey_pub))
            {
                using (StreamReader stream_akey = File.OpenText(file_akey_pub))
                {
                    PemReader pem_reader = new PemReader(stream_akey);
                    key_param = (RsaKeyParameters)pem_reader.ReadObject();
                }
            }
            else
            {
                throw new InvalidParameterException("asymmetric encryption key not provided");
            }

            using (Stream stream_input = FileOrStandardInput(file_input))
            using (Stream stream_output = FileOrStandardOutput(file_output))
            using (BufferedCryptoStream stream_cripto = new BufferedCryptoStream(stream_output, new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesFastEngine()), new Pkcs7Padding())))
            {
                using (GZipStream stream_gzip = new GZipStream(stream_cripto, CompressionMode.Compress))
                {
                    int block_size = stream_cripto.BlockSize;

                    byte[] password_bytes = new byte[password_size];
                    (new SecureRandom()).NextBytes(password_bytes, 0, password_bytes.Length);
                    password = Encoding.ASCII.GetBytes(Convert.ToBase64String(password_bytes));

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

            using (FileStream stream_skey = new FileStream(var_file_password, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                IAsymmetricBlockCipher rsa_cipher = new OaepEncoding(new RsaEngine(), new Sha1Digest(), new byte[0]);
                rsa_cipher.Init(true, key_param);
                byte[] ciphered = rsa_cipher.ProcessBlock(password, 0, password.Length);
                stream_skey.Write(ciphered, 0, ciphered.Length);
            }
        }

        private static void Decrypt(string file_akey_prv, string file_password, string file_input, string file_output, bool uncompress)
        {
            RsaKeyParameters key_param;
            string var_file_password;
            byte[] password;
            byte[] skey;
            byte[] salt;
            byte[] iv;

            if (String.IsNullOrWhiteSpace(file_password))
            {
                var_file_password = file_input + ".pwd";
            }
            else
            {
                var_file_password = file_password;
            }

            if (!String.IsNullOrWhiteSpace(file_akey_prv))
            {
                using (StreamReader stream_akey = File.OpenText(file_akey_prv))
                {
                    PemReader pem_reader = new PemReader(stream_akey);
                    AsymmetricCipherKeyPair key_pair = (AsymmetricCipherKeyPair)pem_reader.ReadObject();
                    key_param = (RsaKeyParameters)key_pair.Private;
                }
            }
            else
            {
                throw new InvalidParameterException("asymmetric encryption key not provided");
            }

            using (MemoryStream memory_skey = new MemoryStream())
            {
                using (FileStream stream_skey = new FileStream(var_file_password, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    byte[] file_bytes = new byte[0x100];
                    do
                    {
                        int bytes_read = stream_skey.Read(file_bytes, 0, file_bytes.Length);
                        if (bytes_read > 0)
                        {
                            memory_skey.Write(file_bytes, 0, bytes_read);
                        }
                        else
                        {
                            break;
                        }
                    } while (true);
                }

                IAsymmetricBlockCipher rsa_cipher = new OaepEncoding(new RsaEngine(), new Sha1Digest(), new byte[0]);
                rsa_cipher.Init(false, key_param);
                string str_password = Encoding.ASCII.GetString(rsa_cipher.ProcessBlock(memory_skey.ToArray(), 0, (int)memory_skey.Length));
                password = Encoding.ASCII.GetBytes(str_password.Split('\r', '\n')[0]);
            }

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
            if (String.IsNullOrWhiteSpace(file_name))
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
            if (String.IsNullOrWhiteSpace(file_name))
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

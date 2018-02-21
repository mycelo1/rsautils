using System;
using System.IO;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Crypto.Stream
{
    public abstract class CryptoStream<T> : System.IO.Stream
    {
        protected System.IO.Stream base_stream;
        protected T base_cipher;

        public virtual int BlockSize { get { return GetBlockSize(); } }
        public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }
        public override long Length { get { throw new NotSupportedException(); } }
        public override bool CanWrite { get { return true; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanRead { get { return false; } }

        public CryptoStream(System.IO.Stream stream, T cipher)
        {
            base_stream = stream;
            base_cipher = cipher;
        }

        public abstract void Init(bool forEncryption, ICipherParameters parameters);
        public abstract int GetOutputSize(int inputLen);
        public abstract int GetBlockSize();

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        protected abstract byte[] ProcessBytes(byte[] buffer, int offset, int count);
        protected abstract byte[] DoFinal();

        public override void Write(byte[] buffer, int offset, int count)
        {
            byte[] bytes_out = ProcessBytes(buffer, offset, count);

            if (bytes_out != null)
            {
                base_stream.Write(bytes_out, 0, bytes_out.Length);
            }
        }

        public override void Flush()
        {
            byte[] bytes_out = DoFinal();

            if (bytes_out != null)
            {
                base_stream.Write(bytes_out, 0, bytes_out.Length);
            }

            try { base_stream.Flush(); } catch { }
        }

        protected override void Dispose(bool disposing) => base.Dispose(disposing);
    }

    public class BufferedCryptoStream : Org.BouncyCastle.Crypto.Stream.CryptoStream<IBufferedCipher>
    {
        public BufferedCryptoStream(System.IO.Stream stream, IBufferedCipher cipher) : base(stream, cipher) { }

        public override void Init(bool forEncryption, ICipherParameters parameters)
        {
            base_cipher.Init(forEncryption, parameters);
        }

        public override int GetOutputSize(int inputLen)
            => base_cipher.GetOutputSize(inputLen);

        public override int GetBlockSize()
            => base_cipher.GetBlockSize();

        protected override byte[] ProcessBytes(byte[] buffer, int offset, int count)
            => base_cipher.ProcessBytes(buffer, offset, count);

        protected override byte[] DoFinal()
            => base_cipher.DoFinal();
    }

    public class AsymmetricCryptoStream : Org.BouncyCastle.Crypto.Stream.CryptoStream<IAsymmetricBlockCipher>
    {
        public AsymmetricCryptoStream(System.IO.Stream stream, IAsymmetricBlockCipher cipher) : base(stream, cipher) { }

        public override void Init(bool forEncryption, ICipherParameters parameters)
            => base_cipher.Init(forEncryption, parameters);

        public override int GetOutputSize(int inputLen) => throw new NotSupportedException();
        public override int GetBlockSize() => throw new NotSupportedException();

        protected override byte[] ProcessBytes(byte[] buffer, int offset, int count)
            => base_cipher.ProcessBlock(buffer, offset, count);

        protected override byte[] DoFinal() => null;
    }
}
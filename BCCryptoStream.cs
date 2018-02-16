using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Crypto.Stream
{
    class BufferedCryptoStream : System.IO.Stream
    {
        protected System.IO.Stream base_stream;
        protected IBufferedCipher base_cipher;

        public virtual int BlockSize { get { return GetBlockSize(); } }
        public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }
        public override long Length { get { throw new NotSupportedException(); } }
        public override bool CanWrite { get { return true; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanRead { get { return false; } }

        public BufferedCryptoStream(System.IO.Stream stream, IBufferedCipher cipher)
        {
            base_stream = stream;
            base_cipher = cipher;
        }

        public virtual void Init(bool forEncryption, ICipherParameters parameters)
        {
            base_cipher.Init(forEncryption, parameters);
        }

        public virtual int GetOutputSize(int inputLen)
        {
            return base_cipher.GetOutputSize(inputLen);
        }

        public virtual int GetBlockSize()
        {
            return base_cipher.GetBlockSize();
        }

        public override int Read(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }
        public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
        public override void SetLength(long value) { throw new NotSupportedException(); }

        public override void Write(byte[] buffer, int offset, int count)
        {
            byte[] bytes_out = base_cipher.ProcessBytes(buffer, offset, count);

            if (bytes_out != null)
            {
                base_stream.Write(bytes_out, 0, bytes_out.Length);
            }
        }

        public override void Flush()
        {
            byte[] bytes_out = base_cipher.DoFinal();

            if (bytes_out != null)
            {
                base_stream.Write(bytes_out, 0, bytes_out.Length);
            }

            try { base_stream.Flush(); } catch { }
        }

        protected override void Dispose(bool disposing) => base.Dispose(disposing);
    }
}
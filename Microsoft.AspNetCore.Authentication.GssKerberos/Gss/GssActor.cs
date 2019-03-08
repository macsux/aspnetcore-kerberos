using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.AspNetCore.Authentication.GssKerberos.Disposables;
using static Microsoft.AspNetCore.Authentication.GssKerberos.Native.Krb5Interop;

namespace Microsoft.AspNetCore.Authentication.GssKerberos.Gss
{
    public abstract class GssActor : IDisposable
    {
        protected IntPtr _context;
        protected GssFlags _actualFlags;

        public GssFlags ActualFlags => _actualFlags;

        public void Dispose()
        {
            if (_context != IntPtr.Zero)
            {
                var majorStatus = gss_delete_sec_context(out var minorStatus, ref _context);
                if (majorStatus != GSS_S_COMPLETE)
                    throw new GssException("The GSS provider returned an error while attempting to delete the GSS Context",
                        majorStatus, minorStatus, GssSpnegoMechOidDesc);
            }
        }

        public byte[] Encrypt(byte[] payload)
        {
            byte[] output;
//            using (var gssMsg = GssBuffer.FromBytes(payload))
            byte[] input = new byte[32];
            input[0] = 3;
            input[1] = 0;
//            using (var gssMsg = GssBuffer.FromString("1234567890123456"))
            using (var gssMsg = GssBuffer.FromBytes(input))
            {
                
                
                var iov = new GssIovBufferDescStruct[4];
                iov[0].type = GSS_IOV_BUFFER_TYPE_HEADER | GSS_IOV_BUFFER_FLAG_ALLOCATE;
                iov[1].type = GSS_IOV_BUFFER_TYPE_DATA;
                iov[1].buffer = gssMsg.Value;
                iov[2].type = GSS_IOV_BUFFER_TYPE_PADDING | GSS_IOV_BUFFER_FLAG_ALLOCATE;
                iov[3].type = GSS_IOV_BUFFER_TYPE_TRAILER | GSS_IOV_BUFFER_FLAG_ALLOCATE;

//                iov[0].type = GSS_IOV_BUFFER_TYPE_SIGN_ONLY | GSS_IOV_BUFFER_FLAG_ALLOCATE;
//                iov[1].type = GSS_IOV_BUFFER_TYPE_DATA;
//                iov[1].buffer = gssMsg.Value;
//                iov[2].type = GSS_IOV_BUFFER_TYPE_SIGN_ONLY | GSS_IOV_BUFFER_FLAG_ALLOCATE;
//                iov[3].type = GSS_IOV_BUFFER_TYPE_HEADER | GSS_IOV_BUFFER_FLAG_ALLOCATE;

                //                iov[0].type = GSS_IOV_BUFFER_TYPE_HEADER;
                //                iov[1].type = GSS_IOV_BUFFER_TYPE_DATA;
                //                iov[1].buffer = gssMsg;
                //                iov[2].type = GSS_IOV_BUFFER_TYPE_PADDING;
                //                iov[3].type = GSS_IOV_BUFFER_TYPE_TRAILER;
                var handle = GCHandle.Alloc(iov, GCHandleType.Pinned);


                try
                {
                    var majorStatus = gss_wrap_iov(out var minorStatus, _context, 1, GSS_C_QOP_DEFAULT, out var confState, iov, iov.Length);
                    if (majorStatus != GSS_S_COMPLETE)
                        throw new GssException("The GSS provider returned an error while attempting to encrypt", majorStatus, minorStatus, GSS_C_NO_OID);
                    output = new byte[gssMsg.Value.length];
                    Marshal.Copy(gssMsg.Value.value, output, 0, (int) gssMsg.Value.length);
                }
                finally
                {
                    handle.Free();
                    var majorStatus = gss_release_iov_buffer(out var minorStatus, iov, iov.Length);
                       
                }
            }

            return output;
        }
    }
}

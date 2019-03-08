using System;
using System.Runtime.InteropServices;
using System.Text;


#pragma warning disable IDE1006
// ReSharper disable InconsistentNaming
// ReSharper disable MemberHidesStaticFromOuterClass

namespace Microsoft.AspNetCore.Authentication.GssKerberos.Native
{
    public static class Krb5Interop
    {
        #region GSS Constants

        internal const int GSS_C_ROUTINE_ERROR_OFFSET = 16;
        internal const uint GSS_S_COMPLETE = 0x00000000;
        internal const uint GSS_S_CONTINUE_NEEDED = 0x00000001;
        internal const uint GSS_C_QOP_DEFAULT = 0;


        #region Flags

        [Flags]
        public enum GssFlags : uint
        {
            GSS_C_DELEG_FLAG = 1,
            GSS_C_MUTUAL_FLAG = 2,
            GSS_C_REPLAY_FLAG = 4,
            GSS_C_SEQUENCE_FLAG = 8,
            GSS_C_CONF_FLAG = 16,
            GSS_C_INTEG_FLAG = 32,
            GSS_C_ANON_FLAG = 64,
            GSS_C_PROT_READY_FLAG = 128,
            GSS_C_TRANS_FLAG = 256,
            GSS_C_DCE_STYLE = 4096,
            GSS_C_IDENTIFY_FLAG = 8192,
            GSS_C_EXTENDED_ERROR_FLAG = 16384,
            GSS_C_DELEG_POLICY_FLAG = 32768
        }

        internal const int GSS_C_DELEG_FLAG = 1;
        internal const int GSS_C_MUTUAL_FLAG = 2;
        internal const int GSS_C_REPLAY_FLAG = 4;
        internal const int GSS_C_SEQUENCE_FLAG = 8;
        internal const int GSS_C_CONF_FLAG = 16;
        internal const int GSS_C_INTEG_FLAG = 32;
        internal const int GSS_C_ANON_FLAG = 64;
        internal const int GSS_C_PROT_READY_FLAG = 128;
        internal const int GSS_C_TRANS_FLAG = 256;
        internal const int GSS_C_DCE_STYLE = 4096;
        internal const int GSS_C_IDENTIFY_FLAG = 8192;
        internal const int GSS_C_EXTENDED_ERROR_FLAG = 16384;
        internal const int GSS_C_DELEG_POLICY_FLAG = 32768;
        #endregion
        #region GSS IOV

        internal const int GSS_IOV_BUFFER_TYPE_EMPTY = 0;
        internal const int GSS_IOV_BUFFER_TYPE_DATA = 1;
        internal const int GSS_IOV_BUFFER_TYPE_HEADER = 2;
        internal const int GSS_IOV_BUFFER_TYPE_MECH_PARAMS = 3;

        internal const int GSS_IOV_BUFFER_TYPE_TRAILER = 7;
        internal const int GSS_IOV_BUFFER_TYPE_PADDING = 9;
        internal const int GSS_IOV_BUFFER_TYPE_STREAM = 10;
        internal const int GSS_IOV_BUFFER_TYPE_SIGN_ONLY = 11;

        internal const uint GSS_IOV_BUFFER_TYPE_FLAG_MASK = 0xffff0000;
        internal const uint GSS_IOV_BUFFER_FLAG_ALLOCATE	=	0x00010000;
        internal const uint GSS_IOV_BUFFER_FLAG_ALLOCATED = 0x00020000;

        internal const uint GSS_IOV_BUFFER_TYPE_FLAG_ALLOCATE = 0x00010000; /* old name */
        internal const uint GSS_IOV_BUFFER_TYPE_FLAG_ALLOCATED = 0x00020000; /* old name */

        #endregion

        #region Routine Errors

        internal const uint GSS_S_BAD_MECH = 1u << GSS_C_ROUTINE_ERROR_OFFSET;
        internal const uint GSS_S_BAD_NAME = 2u << GSS_C_ROUTINE_ERROR_OFFSET;
        internal const uint GSS_S_BAD_NAMETYPE = 3u << GSS_C_ROUTINE_ERROR_OFFSET;
        internal const uint GSS_S_BAD_BINDINGS = 4u << GSS_C_ROUTINE_ERROR_OFFSET;
        internal const uint GSS_S_BAD_STATUS = 5u << GSS_C_ROUTINE_ERROR_OFFSET;
        internal const uint GSS_S_BAD_SIG = 6u << GSS_C_ROUTINE_ERROR_OFFSET;
        internal const uint GSS_S_NO_CRED = 7u << GSS_C_ROUTINE_ERROR_OFFSET;
        internal const uint GSS_S_NO_CONTEXT = 8u << GSS_C_ROUTINE_ERROR_OFFSET;
        internal const uint GSS_S_DEFECTIVE_TOKEN = 9u << GSS_C_ROUTINE_ERROR_OFFSET;
        internal const uint GSS_S_DEFECTIVE_CREDENTIAL = 10u << GSS_C_ROUTINE_ERROR_OFFSET;
        internal const uint GSS_S_CREDENTIALS_EXPIRED = 11u << GSS_C_ROUTINE_ERROR_OFFSET;
        internal const uint GSS_S_CONTEXT_EXPIRED = 12u << GSS_C_ROUTINE_ERROR_OFFSET;
        internal const uint GSS_S_FAILURE = 13u << GSS_C_ROUTINE_ERROR_OFFSET;
        internal const uint GSS_S_BAD_QOP = 14u << GSS_C_ROUTINE_ERROR_OFFSET;
        internal const uint GSS_S_UNAUTHORIZED = 15u << GSS_C_ROUTINE_ERROR_OFFSET;
        internal const uint GSS_S_UNAVAILABLE = 16u << GSS_C_ROUTINE_ERROR_OFFSET;
        internal const uint GSS_S_DUPLICATE_ELEMENT = 17u << GSS_C_ROUTINE_ERROR_OFFSET;
        internal const uint GSS_S_NAME_NOT_MN = 18u << GSS_C_ROUTINE_ERROR_OFFSET;
        #endregion

        internal const uint GSS_C_INDEFINITE = 0xffffffff;

        internal static IntPtr GSS_C_NO_BUFFER = new IntPtr(0);

        internal static GssOidDesc GSS_C_NO_OID = default(GssOidDesc);
        internal static GssOidSet GSS_C_NO_OID_SET = default(GssOidSet);
        #endregion

        #region GSS OIDs
        private static readonly byte[] GssNtHostBasedServiceOid = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x04 };

        internal static GssOidDesc GssNtHostBasedService = new GssOidDesc
        {
            length = 10,
            elements = GCHandle.Alloc(GssNtHostBasedServiceOid, GCHandleType.Pinned).AddrOfPinnedObject()
        };
        
        private static readonly byte[] GssNtPrincipalNameOid = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x01 };

        internal static GssOidDesc GssNtPrincipalName = new GssOidDesc
        {
            length = 10,
            elements = GCHandle.Alloc(GssNtPrincipalNameOid, GCHandleType.Pinned).AddrOfPinnedObject()
        };
        
        /// <summary>
        /// GSS_KRB5_MECH_OID_DESC
        /// </summary>
        private static readonly byte[] GssKrb5MechOid = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02 };
        
        internal static GssOidDesc GssKrb5MechOidDesc = new GssOidDesc
        {
            length = 10,
            elements = GCHandle.Alloc(GssKrb5MechOid, GCHandleType.Pinned).AddrOfPinnedObject()
        };

        /// <summary>
        /// GSS_SPNEGO_MECH_OID_DESC
        /// </summary>
        internal static readonly byte[] GssSpnegoMechOid = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 };

        internal static GssOidDesc GssSpnegoMechOidDesc = new GssOidDesc
        {
            length = 6,
            elements = GCHandle.Alloc(GssSpnegoMechOid, GCHandleType.Pinned).AddrOfPinnedObject()
        };
        
        /// <summary>
        /// GSS_SPNEGO_MECH_OID_DESC Set
        /// </summary>
        internal static GssOidSet GssSpnegoMechOidSet = new GssOidSet
        {
            count = 1,
            elements = GCHandle.Alloc(GssSpnegoMechOidDesc, GCHandleType.Pinned).AddrOfPinnedObject()
        };
        #endregion

        #region GSS Structures

        [StructLayout(LayoutKind.Sequential)]
        public struct GssOidSet
        {
            internal uint count;

            internal IntPtr elements;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct GssIovBufferDescStruct
        {
            internal uint type;
            internal GssBufferStruct buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct GssOidDesc
        {
            internal uint length;

            internal IntPtr elements;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct GssBufferStruct
        {
            /// size_t->unsigned int
            internal uint length;

            /// void*
            internal IntPtr value;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        internal struct GssBufferSet
        {
            /// size_t->unsigned int
           internal uint count;

            /// void*
            internal IntPtr elements;

            public GssBufferStruct[] Buffers
            {
                get
                {
                    var retval = new GssBufferStruct[count];
                    var sizeOfGssBufferStruct = Marshal.SizeOf<GssBufferStruct>();
                    for (int i = 0; i < count; i++)
                    {
                        retval[i] = (GssBufferStruct)Marshal.PtrToStructure(elements + sizeOfGssBufferStruct * i, typeof(GssBufferStruct));
                    }

                    return retval;
                }
            }
        }
        #endregion

        #region KRB5 Structures

        [StructLayout(LayoutKind.Sequential)]
        public struct Krb5Context
        {
            internal int magic;
            internal IntPtr in_tkt_etypes;
            internal IntPtr tgs_etypes;
            internal Krb5OsContext os_context;
            [MarshalAs(UnmanagedType.LPStr)]
            internal string defaultRealm;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct Krb5OsContext
        {
            internal int magic;
            internal int time_offset;
            internal int usec_offset;
            internal int os_flags;
            [MarshalAs(UnmanagedType.LPStr)]
            internal string default_ccname;
        }

        public struct profile_t
        {
            internal long magic;

        }
        #endregion

        #region  MIT Kerberos 5 GSS Platform Thunk

        internal static uint gss_import_name(
            out uint minorStatus,
            ref GssBufferStruct inputNameBuffer,
            ref GssOidDesc inputNameType,
            out IntPtr outputName)
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? Environment.Is64BitProcess
                    ? Win64.gss_import_name(out minorStatus, ref inputNameBuffer, ref inputNameType, out outputName)
                    : Win32.gss_import_name(out minorStatus, ref inputNameBuffer, ref inputNameType, out outputName)
                : Linux.gss_import_name(out minorStatus, ref inputNameBuffer, ref inputNameType, out outputName);
        }

        internal static uint gss_acquire_cred(
            out uint minorStatus,
            IntPtr desiredName,
            uint timeRequired,
            ref GssOidSet desiredMechanisms,
            int credentialUsage,
            ref IntPtr credentialHandle,
            IntPtr actualMech,
            out uint expiryTime)
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? Environment.Is64BitProcess
                    ? Win64.gss_acquire_cred(out minorStatus, desiredName, timeRequired, ref desiredMechanisms,
                        credentialUsage, out credentialHandle, actualMech, out expiryTime)
                    : Win32.gss_acquire_cred(out minorStatus, desiredName, timeRequired, ref desiredMechanisms,
                        credentialUsage, out credentialHandle, actualMech, out expiryTime)
                : Linux.gss_acquire_cred(out minorStatus, desiredName, timeRequired, ref desiredMechanisms,
                    credentialUsage, out credentialHandle, actualMech, out expiryTime);
        }

        internal static uint gss_acquire_cred_with_password(
            out uint minorStatus,
            IntPtr desiredName,
            ref GssBufferStruct password,
            uint timeRequired,
            ref GssOidSet desiredMechanisms,
            int credentialUsage,
            ref IntPtr credentialHandle,
            IntPtr actualMechs,
            out uint expiryTime)
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? Environment.Is64BitProcess
                    ? Win64.gss_acquire_cred_with_password(out minorStatus, desiredName, ref password, timeRequired,
                        ref desiredMechanisms, credentialUsage, ref credentialHandle, actualMechs, out expiryTime)
                    : Win32.gss_acquire_cred_with_password(out minorStatus, desiredName, ref password, timeRequired,
                        ref desiredMechanisms, credentialUsage, ref credentialHandle, actualMechs, out expiryTime)
                : Linux.gss_acquire_cred_with_password(out minorStatus, desiredName, ref password, timeRequired,
                    ref desiredMechanisms, credentialUsage, ref credentialHandle, actualMechs, out expiryTime);
        }

        internal static uint gss_inquire_name(
            out uint minorStatus,
            IntPtr name,
            out int mechName,
            out GssOidSet oids,
            out IntPtr attrs)
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? Environment.Is64BitProcess
                    ? Win64.gss_inquire_name(out minorStatus, name, out mechName, out oids, out attrs)
                    : Win32.gss_inquire_name(out minorStatus, name, out mechName, out oids, out attrs)
                : Linux.gss_inquire_name(out minorStatus, name, out mechName, out oids, out attrs);
        }

        internal static uint gss_get_name_attribute(
            out uint minorStatus,
            IntPtr name,
            ref GssBufferStruct attribute,
            out int authenticated,
            out int complete,
            out GssBufferStruct value,
            out GssBufferStruct displayValue,
            ref int more)
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? Environment.Is64BitProcess
                    ? Win64.gss_get_name_attribute(out minorStatus, name, ref attribute, out authenticated,
                        out complete, out value, out displayValue, ref more)
                    : Win32.gss_get_name_attribute(out minorStatus, name, ref attribute, out authenticated,
                        out complete, out value, out displayValue, ref more)
                : Linux.gss_get_name_attribute(out minorStatus, name, ref attribute, out authenticated, out complete,
                    out value, out displayValue, ref more);
        }

        internal static uint gss_init_sec_context(
            out uint minorStatus,
            IntPtr claimantCredHandle,
            ref IntPtr contextHandle,
            IntPtr targetName,
            ref GssOidDesc mechType,
            GssFlags reqFlags,
            uint timeReq,
            IntPtr inputChanBindings,
            ref GssBufferStruct inputToken,
            IntPtr actualMechType,
            out GssBufferStruct outputToken,
            out GssFlags retFlags,
            IntPtr timeRec)
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? Environment.Is64BitProcess
                    ? Win64.gss_init_sec_context(out minorStatus, claimantCredHandle, ref contextHandle, targetName,
                        ref mechType, reqFlags, timeReq, inputChanBindings, ref inputToken, actualMechType,
                        out outputToken, out retFlags, timeRec)
                    : Win32.gss_init_sec_context(out minorStatus, claimantCredHandle, ref contextHandle, targetName,
                        ref mechType, reqFlags, timeReq, inputChanBindings, ref inputToken, actualMechType,
                        out outputToken, out retFlags, timeRec)
                : Linux.gss_init_sec_context(out minorStatus, claimantCredHandle, ref contextHandle, targetName,
                    ref mechType, reqFlags, timeReq, inputChanBindings, ref inputToken, actualMechType,
                    out outputToken, out retFlags, timeRec);
        }

        internal static uint gss_accept_sec_context(
            out uint minorStatus,
            ref IntPtr contextHandle,
            IntPtr acceptorCredHandle,
            ref GssBufferStruct inputToken,
            IntPtr channelBindings,
            out IntPtr sourceName,
            IntPtr mechType,
            out GssBufferStruct outputToken,
            out uint retFlags,
            out uint timeRec,
            IntPtr delegated)
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? Environment.Is64BitProcess
                    ? Win64.gss_accept_sec_context(out minorStatus, ref contextHandle, acceptorCredHandle,
                        ref inputToken, channelBindings, out sourceName, mechType, out outputToken, out retFlags,
                        out timeRec, delegated)
                    : Win32.gss_accept_sec_context(out minorStatus, ref contextHandle, acceptorCredHandle,
                        ref inputToken, channelBindings, out sourceName, mechType, out outputToken, out retFlags,
                        out timeRec, delegated)
                : Linux.gss_accept_sec_context(out minorStatus, ref contextHandle, acceptorCredHandle,
                    ref inputToken, channelBindings, out sourceName, mechType, out outputToken, out retFlags,
                    out timeRec, delegated);
        }

        internal static uint gss_display_name(
                out uint minorStatus,
                IntPtr inputName,
                out GssBufferStruct NameBuffer,
                out GssOidDesc nameType)
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? Environment.Is64BitProcess
                    ? Win64.gss_display_name(out minorStatus, inputName, out NameBuffer, out nameType)
                    : Win32.gss_display_name(out minorStatus, inputName, out NameBuffer, out nameType)
                : Linux.gss_display_name(out minorStatus, inputName, out NameBuffer, out nameType);
        }

        internal static uint gss_display_status(
            out uint minorStatus,
            uint status,
            int statusType,
            ref GssOidDesc mechType,
            ref IntPtr messageContext,
            ref GssBufferStruct statusString)
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? Environment.Is64BitProcess
                    ? Win64.gss_display_status(out minorStatus, status, statusType, ref mechType, ref messageContext,
                        ref statusString)
                    : Win32.gss_display_status(out minorStatus, status, statusType, ref mechType, ref messageContext,
                        ref statusString)
                : Linux.gss_display_status(out minorStatus, status, statusType, ref mechType, ref messageContext,
                    ref statusString);
        }

        internal static uint gss_release_buffer(
            out uint minorStatus,
            ref GssBufferStruct buffer)
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? Environment.Is64BitProcess
                    ? Win64.gss_release_buffer(out minorStatus, ref buffer)
                    : Win32.gss_release_buffer(out minorStatus, ref buffer)
                : Linux.gss_release_buffer(out minorStatus, ref buffer);
        }

        internal static uint gss_delete_sec_context(
            out uint minorStatus,
            ref IntPtr contextHandle)
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
           ? Environment.Is64BitProcess
               ? Win64.gss_delete_sec_context(out minorStatus, ref contextHandle, GSS_C_NO_BUFFER)
               : Win32.gss_delete_sec_context(out minorStatus, ref contextHandle, GSS_C_NO_BUFFER)
           : Linux.gss_delete_sec_context(out minorStatus, ref contextHandle, GSS_C_NO_BUFFER);
        }

        internal static uint gss_release_name(
            out uint minorStatus,
            ref IntPtr inputName)
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? Environment.Is64BitProcess
                    ? Win64.gss_release_name(out minorStatus, ref inputName)
                    : Win32.gss_release_name(out minorStatus, ref inputName)
                : Linux.gss_release_name(out minorStatus, ref inputName);
        }

        internal static uint gss_release_cred(
            out uint minorStatus,
            ref IntPtr credentialHandle)
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? Environment.Is64BitProcess
                    ? Win64.gss_release_cred(out minorStatus, ref credentialHandle)
                    : Win32.gss_release_cred(out minorStatus, ref credentialHandle)
                : Linux.gss_release_cred(out minorStatus, ref credentialHandle);
        }

        internal static uint gss_wrap_iov(
            out uint minorStatus,
            IntPtr contextHandle,
            int conf_req_flag,
            uint qop_req,
            out int confState,
            GssIovBufferDescStruct[] iov,
            int iov_count)
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? Environment.Is64BitProcess
                    ? Win64.gss_wrap_iov(out minorStatus, contextHandle, conf_req_flag, qop_req, out confState, iov, iov_count)
                    : Win32.gss_wrap_iov(out minorStatus, ref contextHandle, conf_req_flag, qop_req, out confState, iov, iov_count)
                : Linux.gss_wrap_iov(out minorStatus, contextHandle, conf_req_flag, qop_req, out confState, iov, iov_count);
        }

        internal static uint gss_unwrap_iov(
            out uint minorStatus,
            IntPtr contextHandle,
            out int confState,
            ref uint qop_state,
            GssIovBufferDescStruct[] iov,
            int iovCount)
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? Environment.Is64BitProcess
                    ? Win64.gss_unwrap_iov(out minorStatus, contextHandle, out confState, ref qop_state, iov, iovCount)
                    : Win32.gss_unwrap_iov(out minorStatus, contextHandle, out confState, ref qop_state, iov, iovCount)
                : Linux.gss_unwrap_iov(out minorStatus, contextHandle, out confState, ref qop_state, iov, iovCount);
        }

        internal static uint gss_wrap_iov_length(
            out uint minorStatus,
            IntPtr contextHandle,
            int conf_req_flag,
            uint qop_req,
            out int confState,
            GssIovBufferDescStruct[] iov,
            int iov_count)
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? Environment.Is64BitProcess
                    ? Win64.gss_wrap_iov_length(out minorStatus, contextHandle, conf_req_flag, qop_req, out confState, iov, iov_count)
                    : Win32.gss_wrap_iov_length(out minorStatus, contextHandle, conf_req_flag, qop_req, out confState, iov, iov_count)
                : Linux.gss_wrap_iov_length(out minorStatus,  contextHandle, conf_req_flag, qop_req, out confState, iov, iov_count);
        }

        internal static uint gss_release_iov_buffer(
            out uint minorStatus,
            GssIovBufferDescStruct[] iov,
            int iov_count)
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? Environment.Is64BitProcess
                    ? Win64.gss_release_iov_buffer(out minorStatus, iov, iov_count)
                    : Win32.gss_release_iov_buffer(out minorStatus, iov, iov_count)
                : Linux.gss_release_iov_buffer(out minorStatus, iov, iov_count);
        }


        #endregion

        #region MIT Kerberos 5 GSS Bindings Windows 32bit
        private static class Win32
        {
            private const string GssModulename = "gssapi32.dll";

            [DllImport(GssModulename, EntryPoint = "gss_import_name")]

            internal static extern uint gss_import_name(
                out uint minorStatus,
                ref GssBufferStruct inputNameBuffer,
                ref GssOidDesc inputNameType,
                out IntPtr outputName);

            [DllImport(GssModulename, EntryPoint = "gss_acquire_cred")]
            internal static extern uint gss_acquire_cred(
                out uint minorStatus,
                IntPtr desiredName,
                uint timeRequired,
                ref GssOidSet desiredMechanisms,
                int credentialUsage,
                out IntPtr credentialHandle,
                IntPtr actualMech,
                out uint expiryTime);

            [DllImport(GssModulename, EntryPoint = "gss_acquire_cred_with_password")]
            internal static extern uint gss_acquire_cred_with_password(
                out uint minorStatus,
                IntPtr desiredName,
                ref GssBufferStruct password,
                uint timeRequired,
                ref GssOidSet desiredMechanisms,
                int credentialUsage,
                ref IntPtr credentialHandle,
                IntPtr actualMechs,
                out uint expiryTime);

            [DllImport(GssModulename, EntryPoint = "gss_inquire_name")]
            internal static extern uint gss_inquire_name(
                out uint minorStatus,
                IntPtr name,
                out int mechName,
                out GssOidSet oids,
                out IntPtr attrs);

            [DllImport(GssModulename, EntryPoint = "gss_get_name_attribute")]
            internal static extern uint gss_get_name_attribute(
                out uint minorStatus,
                IntPtr name,
                ref GssBufferStruct attribute,
                out int authenticated,
                out int complete,
                out GssBufferStruct value,
                out GssBufferStruct displayValue,
                ref int more);

            [DllImport(GssModulename, EntryPoint = "gss_init_sec_context")]
            internal static extern uint gss_init_sec_context(
                out uint minorStatus,
                IntPtr claimantCredHandle,
                ref IntPtr contextHandle,
                IntPtr targetName,
                ref GssOidDesc mechType,
                GssFlags reqFlags,
                uint timeReq,
                IntPtr inputChanBindings,
                ref GssBufferStruct inputToken,
                IntPtr actualMechType,
                out GssBufferStruct outputToken,
                out GssFlags retFlags,
                IntPtr timeRec);

            [DllImport(GssModulename, EntryPoint = "gss_accept_sec_context")]
            internal static extern uint gss_accept_sec_context(
                out uint minorStatus,
                ref IntPtr contextHandle,
                IntPtr acceptorCredHandle,
                ref GssBufferStruct inputToken,
                IntPtr channelBindings,
                out IntPtr sourceName,
                IntPtr mechType,
                out GssBufferStruct outputToken,
                out uint retFlags,
                out uint timeRec,
                IntPtr delegated);

            [DllImport(GssModulename, EntryPoint = "gss_display_name")]
            internal static extern uint gss_display_name(
                out uint minorStatus,
                IntPtr inputName,
                out GssBufferStruct NameBuffer,
                out GssOidDesc nameType);

            [DllImport(GssModulename, EntryPoint = "gss_display_status")]
            internal static extern uint gss_display_status(
                out uint minorStatus,
                uint status,
                int statusType,
                ref GssOidDesc mechType,
                ref IntPtr messageContext,
                ref GssBufferStruct statusString);

            [DllImport(GssModulename, EntryPoint = "gss_release_buffer")]
            internal static extern uint gss_release_buffer(
                out uint minorStatus,
                ref GssBufferStruct buffer);

            [DllImport(GssModulename, EntryPoint = "gss_release_cred")]
            internal static extern uint gss_release_cred(
                out uint minorStatus,
                ref IntPtr credentialHandle);

            [DllImport(GssModulename, EntryPoint = "gss_release_name")]
            internal static extern uint gss_release_name(
                out uint minorStatus,
                ref IntPtr inputName);

            [DllImport(GssModulename, EntryPoint = "gss_delete_sec_context")]
            internal static extern uint gss_delete_sec_context(
                out uint minorStatus,
                ref IntPtr contextHandle,
                IntPtr outputToken);

            [DllImport(GssModulename, EntryPoint = "gss_wrap_iov")]
            internal static extern uint gss_wrap_iov(
                out uint minorStatus,
                ref IntPtr contextHandle,
                int confReqFlag, 
                uint qopReq,
                out int confState,
                [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 6)]
                GssIovBufferDescStruct[] iov,
                int iovCount);

            [DllImport(GssModulename, EntryPoint = "gss_unwrap_iov")]
            internal static extern uint gss_unwrap_iov(
                out uint minorStatus,
                IntPtr contextHandle,
                out int confState,
                ref uint qop_state,
                [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 5)]
                GssIovBufferDescStruct[] iov,
                int iovCount);

            [DllImport(GssModulename, EntryPoint = "gss_wrap_iov_length")]
            internal static extern uint gss_wrap_iov_length(
                out uint minorStatus,
                IntPtr contextHandle,
                int confReqFlag,
                uint qopReq,
                out int confState,
                [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 6)]
                GssIovBufferDescStruct[] iov,
                int iovCount);

            [DllImport(GssModulename, EntryPoint = "gss_release_iov_buffer")]
            internal static extern uint gss_release_iov_buffer(
                out uint minorStatus,
                [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2)]
                GssIovBufferDescStruct[] iov,
                int iovCount);
        }
        #endregion

        #region MIT Kerberos 5 GSS Bindings Windows 64bit
        private static class Win64
        {
            private const string GssModulename = "gssapi64.dll";

            [DllImport(GssModulename, EntryPoint = "gss_import_name")]
            internal static extern uint gss_import_name(
                out uint minorStatus,
                ref GssBufferStruct inputNameBuffer,
                ref GssOidDesc inputNameType,
                out IntPtr outputName);

            [DllImport(GssModulename, EntryPoint = "gss_acquire_cred")]
            internal static extern uint gss_acquire_cred(
                out uint minorStatus,
                IntPtr desiredName,
                uint timeRequired,
                ref GssOidSet desiredMechanisms,
                int credentialUsage,
                out IntPtr credentialHandle,
                IntPtr actualMechs,
                out uint expiryTime);

            [DllImport(GssModulename, EntryPoint = "gss_acquire_cred_with_password")]
            internal static extern uint gss_acquire_cred_with_password(
                out uint minorStatus,
                IntPtr desiredName,
                ref GssBufferStruct password,
                uint timeRequired,
                ref GssOidSet desiredMechanisms,
                int credentialUsage,
                ref IntPtr credentialHandle,
                IntPtr actualMech,
                out uint expiryTime);

            [DllImport(GssModulename, EntryPoint = "gss_inquire_name")]
            internal static extern uint gss_inquire_name(
                out uint minorStatus,
                IntPtr name,
                out int mechName,
                out GssOidSet oids,
                out IntPtr attrs);

            [DllImport(GssModulename, EntryPoint = "gss_get_name_attribute")]
            internal static extern uint gss_get_name_attribute(
                out uint minorStatus,
                IntPtr name,
                ref GssBufferStruct attribute,
                out int authenticated,
                out int complete,
                out GssBufferStruct value,
                out GssBufferStruct displayValue,
                ref int more);

            [DllImport(GssModulename, EntryPoint = "gss_init_sec_context")]
            internal static extern uint gss_init_sec_context(
                out uint minorStatus,
                IntPtr claimantCredHandle,
                ref IntPtr contextHandle,
                IntPtr targetName,
                ref GssOidDesc mechType,
                GssFlags reqFlags,
                uint timeReq,
                IntPtr inputChanBindings,
                ref GssBufferStruct inputToken,
                IntPtr actualMechType,
                out GssBufferStruct outputToken,
                out GssFlags retFlags,
                IntPtr timeRec);

            [DllImport(GssModulename, EntryPoint = "gss_accept_sec_context")]
            internal static extern uint gss_accept_sec_context(
                out uint minorStatus,
                ref IntPtr contextHandle,
                IntPtr acceptorCredHandle,
                ref GssBufferStruct inputToken,
                IntPtr channelBindings,
                out IntPtr sourceName,
                IntPtr mechType,
                out GssBufferStruct outputToken,
                out uint retFlags,
                out uint timeRec,
                IntPtr delegated);

            [DllImport(GssModulename, EntryPoint = "gss_display_name")]
            internal static extern uint gss_display_name(
                out uint minorStatus,
                IntPtr inputName,
                out GssBufferStruct NameBuffer,
                out GssOidDesc nameType);

            [DllImport(GssModulename, EntryPoint = "gss_display_status")]
            internal static extern uint gss_display_status(
                out uint minorStatus,
                uint status,
                int statusType,
                ref GssOidDesc mechType,
                ref IntPtr messageContext,
                ref GssBufferStruct statusString);

            [DllImport(GssModulename, EntryPoint = "gss_release_buffer")]
            internal static extern uint gss_release_buffer(
                out uint minorStatus,
                ref GssBufferStruct buffer);

            [DllImport(GssModulename, EntryPoint = "gss_release_cred")]
            internal static extern uint gss_release_cred(
                out uint minorStatus,
                ref IntPtr credentialHandle);

            [DllImport(GssModulename, EntryPoint = "gss_release_name")]
            internal static extern uint gss_release_name(
                out uint minorStatus,
                ref IntPtr inputName);

            [DllImport(GssModulename, EntryPoint = "gss_delete_sec_context")]
            internal static extern uint gss_delete_sec_context(
                out uint minorStatus,
                ref IntPtr contextHandle,
                IntPtr outputToken);

            [DllImport(GssModulename, EntryPoint = "gss_wrap_iov")]
            internal static extern uint gss_wrap_iov(
                out uint minorStatus,
                IntPtr contextHandle,
                int confReqFlag,
                uint qopReq,
                out int confState,
                [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 6)]
                GssIovBufferDescStruct[] iov,
                int iovCount);

            [DllImport(GssModulename, EntryPoint = "gss_unwrap_iov")]
            internal static extern uint gss_unwrap_iov(
                out uint minorStatus,
                IntPtr contextHandle,
                out int confState,
                ref uint qop_state,
                [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 5)]
                GssIovBufferDescStruct[] iov,
                int iovCount);

            [DllImport(GssModulename, EntryPoint = "gss_wrap_iov_length")]
            internal static extern uint gss_wrap_iov_length(
                out uint minorStatus,
                IntPtr contextHandle,
                int confReqFlag,
                uint qopReq,
                out int confState,
                [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 6)]
                GssIovBufferDescStruct[] iov,
                int iovCount);

            [DllImport(GssModulename, EntryPoint = "gss_release_iov_buffer")]
            internal static extern uint gss_release_iov_buffer(
                out uint minorStatus,
                [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2)]
                GssIovBufferDescStruct[] iov,
                int iovCount);
        }
        #endregion

        #region Linux MIT Kerberos 5 GSS Bindings

        private static class Linux
        {
            private const string GssModulename = "libgssapi_krb5.so.2";

            [DllImport(GssModulename, EntryPoint = "gss_import_name")]
            internal static extern uint gss_import_name(
                out uint minorStatus,
                ref GssBufferStruct inputNameBuffer,
                ref GssOidDesc inputNameType,
                out IntPtr outputName);


            [DllImport(GssModulename, EntryPoint = "gss_acquire_cred")]
            internal static extern uint gss_acquire_cred(
                out uint minorStatus,
                IntPtr desiredName,
                uint timeRequired,
                ref GssOidSet desiredMechanisms,
                int credentialUsage,
                out IntPtr credentialHandle,
                IntPtr actualMech,
                out uint expiryTime);

            [DllImport(GssModulename, EntryPoint = "gss_acquire_cred_with_password")]
            internal static extern uint gss_acquire_cred_with_password(
                out uint minorStatus,
                IntPtr desiredName,
                ref GssBufferStruct password,
                uint timeRequired,
                ref GssOidSet desiredMechanisms,
                int credentialUsage,
                ref IntPtr credentialHandle,
                IntPtr actualMechs,
                out uint expiryTime);

            [DllImport(GssModulename, EntryPoint = "gss_inquire_name")]
            internal static extern uint gss_inquire_name(
                out uint minorStatus,
                IntPtr name,
                out int mechName,
                out GssOidSet oids,
                out IntPtr attrs);

            [DllImport(GssModulename, EntryPoint = "gss_get_name_attribute")]
            internal static extern uint gss_get_name_attribute(
                out uint minorStatus,
                IntPtr name,
                ref GssBufferStruct attribute,
                out int authenticated,
                out int complete,
                out GssBufferStruct value,
                out GssBufferStruct displayValue,
                ref int more);

            [DllImport(GssModulename, EntryPoint = "gss_init_sec_context")]
            internal static extern uint gss_init_sec_context(
                out uint minorStatus,
                IntPtr claimantCredHandle,
                ref IntPtr contextHandle,
                IntPtr targetName,
                ref GssOidDesc mechType,
                GssFlags reqFlags,
                uint timeReq,
                IntPtr inputChanBindings,
                ref GssBufferStruct inputToken,
                IntPtr actualMechType,
                out GssBufferStruct outputToken,
                out GssFlags retFlags,
                IntPtr timeRec);

            [DllImport(GssModulename, EntryPoint = "gss_accept_sec_context")]
            internal static extern uint gss_accept_sec_context(
                out uint minorStatus,
                ref IntPtr contextHandle,
                IntPtr acceptorCredHandle,
                ref GssBufferStruct inputToken,
                IntPtr channelBindings,
                out IntPtr sourceName,
                IntPtr mechType,
                out GssBufferStruct outputToken,
                out uint retFlags,
                out uint timeRec,
                IntPtr delegated);

            [DllImport(GssModulename, EntryPoint = "gss_display_name")]
            internal static extern uint gss_display_name(
                out uint minorStatus,
                IntPtr inputName,
                out GssBufferStruct NameBuffer,
                out GssOidDesc nameType);

            [DllImport(GssModulename, EntryPoint = "gss_display_status")]
            internal static extern uint gss_display_status(
                out uint minorStatus,
                uint status,
                int statusType,
                ref GssOidDesc mechType,
                ref IntPtr messageContext,
                ref GssBufferStruct statusString);

            [DllImport(GssModulename, EntryPoint = "gss_release_buffer")]
            internal static extern uint gss_release_buffer(
                out uint minorStatus,
                ref GssBufferStruct buffer);

            [DllImport(GssModulename, EntryPoint = "gss_release_cred")]
            internal static extern uint gss_release_cred(
                out uint minorStatus,
                ref IntPtr credentialHandle);

            [DllImport(GssModulename, EntryPoint = "gss_release_name")]
            internal static extern uint gss_release_name(
                out uint minorStatus,
                ref IntPtr inputName);

            [DllImport(GssModulename, EntryPoint = "gss_delete_sec_context")]
            internal static extern uint gss_delete_sec_context(
                out uint minorStatus,
                ref IntPtr contextHandle,
                IntPtr outputToken);

            [DllImport(GssModulename, EntryPoint = "gss_wrap_iov")]
            internal static extern uint gss_wrap_iov(
                out uint minorStatus,
                IntPtr contextHandle,
                int confReqFlag,
                uint qopReq,
                out int confState,
                [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 6)]
                GssIovBufferDescStruct[] iov,
                int iovCount);

            [DllImport(GssModulename, EntryPoint = "gss_unwrap_iov")]
            internal static extern uint gss_unwrap_iov(
                out uint minorStatus,
                IntPtr contextHandle,
                out int confState,
                ref uint qop_state,
                [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 5)]
                GssIovBufferDescStruct[] iov,
                int iovCount);

            [DllImport(GssModulename, EntryPoint = "gss_wrap_iov_length")]
            internal static extern uint gss_wrap_iov_length(
                out uint minorStatus,
                IntPtr contextHandle,
                int confReqFlag,
                uint qopReq,
                out int confState,
                [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 6)]
                GssIovBufferDescStruct[] iov,
                int iovCount);

            [DllImport(GssModulename, EntryPoint = "gss_release_iov_buffer")]
            internal static extern uint gss_release_iov_buffer(
                out uint minorStatus,
                [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2)]
                GssIovBufferDescStruct[] iov,
                int iovCount);
        }
        #endregion
    }
}

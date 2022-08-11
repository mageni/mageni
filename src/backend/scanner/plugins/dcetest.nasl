###############################################################################
# OpenVAS Vulnerability Test
# $Id: dcetest.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# DCE/RPC and MSRPC Services Enumeration
#
# Authors:
# This code is 100% based on 'dcetest', by Dave Aitel, a free (GPL'ed)
# C program available at http://www.immunitysec.com/tools.html
# (or http://www.atstake.com)
# NASL translation by Renaud Deraison
# and Pavel Kankovsky, DCIT s.r.o. <kan@dcit.cz>
#
# Copyright:
# Copyright (C) 2001 Dave Aitel (ported to NASL by rd and Pavel Kankovsky)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

# DCEMAP
#
# Does a 'portmap-like' request to the remote host, to
# to determine what DCE/MS RPC services are running.
#
# See also:
# CAE Specification, DCE 1.1: Remote Procedure Call, Doc. No. C706
# http://www.opengroup.org/products/publications/catalog/c706.htm

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108044");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("DCE/RPC and MSRPC Services Enumeration");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2001 Dave Aitel (ported to NASL by rd and Pavel Kankovsky)");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports(135);

  script_tag(name:"summary", value:"Distributed Computing Environment / Remote Procedure Calls (DCE/RPC) or MSRPC services running
  on the remote host can be enumerated by connecting on port 135 and doing the appropriate queries.

  The actual reporting takes place in the NVT 'DCE/RPC and MSRPC Services Enumeration Reporting'
  (OID: 1.3.6.1.4.1.25623.1.0.10736)");

  script_tag(name:"impact", value:"An attacker may use this fact to gain more knowledge
  about the remote host.");

  script_tag(name:"solution", value:"Filter incoming traffic to this port.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("host_details.inc");

# nb: Some of the enumerated tcp/udp ports might expose several services
# Those lists are used for handling a list of already registered so we
# don't register those services multiple times on the same port.
udp_services_list = make_list();
tcp_services_list = make_list();

# Ref : http://www.hsc.fr/ressources/articles/win_net_srv/index.html.en by Jean-Baptiste Marchand
rpc_svc_pipes["1ff70682-0a51-30e8-076d-740be8cee98b"] = "atsvc";
rpc_svc_processes["1ff70682-0a51-30e8-076d-740be8cee98b"] = "mstask.exe";
rpc_svc_name["1ff70682-0a51-30e8-076d-740be8cee98b"] = "Scheduler service";
rpc_svc_pipes["3faf4738-3a21-4307-b46c-fdda9bb8c0d5"] = "AudioSrv";
rpc_svc_processes["3faf4738-3a21-4307-b46c-fdda9bb8c0d5"] = "AudioSrv";
rpc_svc_name["3faf4738-3a21-4307-b46c-fdda9bb8c0d5"] = "Windows Audio service";
rpc_svc_pipes["6bffd098-a112-3610-9833-012892020162"] = "ntsvcs";
rpc_svc_processes["6bffd098-a112-3610-9833-012892020162"] = "Browser";
rpc_svc_name["6bffd098-a112-3610-9833-012892020162"] = "Computer Browser";
rpc_svc_pipes["91ae6020-9e3c-11cf-8d7c-00aa00c091be"] = "cert";
rpc_svc_processes["91ae6020-9e3c-11cf-8d7c-00aa00c091be"] = "certsrv.exe";
rpc_svc_name["91ae6020-9e3c-11cf-8d7c-00aa00c091be"] = "Certificate service";
rpc_svc_pipes["5ca4a760-ebb1-11cf-8611-00a0245420ed"] = "Ctx_WinStation_API_service";
rpc_svc_processes["5ca4a760-ebb1-11cf-8611-00a0245420ed"] = "termsrv.exe";
rpc_svc_name["5ca4a760-ebb1-11cf-8611-00a0245420ed"] = "Terminal Services remote management";
rpc_svc_pipes["c8cb7687-e6d3-11d2-a958-00c04f682e16"] = "DAV RPC SERVICE";
rpc_svc_processes["c8cb7687-e6d3-11d2-a958-00c04f682e16"] = "WebClient";
rpc_svc_name["c8cb7687-e6d3-11d2-a958-00c04f682e16"] = "WebDAV client";
rpc_svc_pipes["50abc2a4-574d-40b3-9d66-ee4fd5fba076"] = "dnsserver";
rpc_svc_processes["50abc2a4-574d-40b3-9d66-ee4fd5fba076"] = "dns.exe";
rpc_svc_name["50abc2a4-574d-40b3-9d66-ee4fd5fba076"] = "DNS Server";
rpc_svc_pipes["e1af8308-5d1f-11c9-91a4-08002b14a0fa"] = "epmapper";
rpc_svc_processes["e1af8308-5d1f-11c9-91a4-08002b14a0fa"] = "RpcSs";
rpc_svc_name["e1af8308-5d1f-11c9-91a4-08002b14a0fa"] = "RPC endpoint mapper";
rpc_svc_pipes["82273fdc-e32a-18c3-3f78-827929dc23ea"] = "ntsvcs";
rpc_svc_processes["82273fdc-e32a-18c3-3f78-827929dc23ea"] = "Eventlog";
rpc_svc_name["82273fdc-e32a-18c3-3f78-827929dc23ea"] = "Eventlog service";
rpc_svc_pipes["3d267954-eeb7-11d1-b94e-00c04fa3080d"] = "HydraLsPipe";
rpc_svc_processes["3d267954-eeb7-11d1-b94e-00c04fa3080d"] = "lserver.exe";
rpc_svc_name["3d267954-eeb7-11d1-b94e-00c04fa3080d"] = "Terminal Server Licensing";
rpc_svc_pipes["894de0c0-0d55-11d3-a322-00c04fa321a1"] = "InitShutdown";
rpc_svc_processes["894de0c0-0d55-11d3-a322-00c04fa321a1"] = "winlogon.exe";
rpc_svc_name["894de0c0-0d55-11d3-a322-00c04fa321a1"] = "(Remote) system shutdown";
rpc_svc_pipes["8d0ffe72-d252-11d0-bf8f-00c04fd9126b"] = "keysvc";
rpc_svc_processes["8d0ffe72-d252-11d0-bf8f-00c04fd9126b"] = "CryptSvc";
rpc_svc_name["8d0ffe72-d252-11d0-bf8f-00c04fd9126b"] = "Cryptographic services";
rpc_svc_pipes["0d72a7d4-6148-11d1-b4aa-00c04fb66ea0"] = "keysvc";
rpc_svc_processes["0d72a7d4-6148-11d1-b4aa-00c04fb66ea0"] = "CryptSvc";
rpc_svc_name["0d72a7d4-6148-11d1-b4aa-00c04fb66ea0"] = "Cryptographic services";
rpc_svc_pipes["d6d70ef0-0e3b-11cb-acc3-08002b1d29c4"] = "locator";
rpc_svc_processes["d6d70ef0-0e3b-11cb-acc3-08002b1d29c4"] = "locator.exe";
rpc_svc_name["d6d70ef0-0e3b-11cb-acc3-08002b1d29c4"] = "RPC Locator service";
rpc_svc_pipes["342cfd40-3c6c-11ce-a893-08002b2e9c6d"] = "llsrpc";
rpc_svc_processes["342cfd40-3c6c-11ce-a893-08002b2e9c6d"] = "llssrv.exe";
rpc_svc_name["342cfd40-3c6c-11ce-a893-08002b2e9c6d"] = "License Logging service";
rpc_svc_pipes["12345778-1234-abcd-ef00-0123456789ab"] = "lsass";
rpc_svc_processes["12345778-1234-abcd-ef00-0123456789ab"] = "lsass.exe";
rpc_svc_name["12345778-1234-abcd-ef00-0123456789ab"] = "LSA access";
rpc_svc_pipes["3919286a-b10c-11d0-9ba8-00c04fd92ef5"] = "lsass";
rpc_svc_processes["3919286a-b10c-11d0-9ba8-00c04fd92ef5"] = "lsass.exe";
rpc_svc_name["3919286a-b10c-11d0-9ba8-00c04fd92ef5"] = "LSA DS access";
rpc_svc_pipes["5a7b91f8-ff00-11d0-a9b2-00c04fb6e6fc"] = "ntsvcs";
rpc_svc_processes["5a7b91f8-ff00-11d0-a9b2-00c04fb6e6fc"] = "messenger";
rpc_svc_name["5a7b91f8-ff00-11d0-a9b2-00c04fb6e6fc"] = "Messenger service";
rpc_svc_pipes["4fc742e0-4a10-11cf-8273-00aa004ae673"] = "netdfs";
rpc_svc_processes["4fc742e0-4a10-11cf-8273-00aa004ae673"] = "Dfssvc";
rpc_svc_name["4fc742e0-4a10-11cf-8273-00aa004ae673"] = "Distributed File System service";
rpc_svc_pipes["12345678-1234-abcd-ef00-01234567cffb"] = "lsass";
rpc_svc_processes["12345678-1234-abcd-ef00-01234567cffb"] = "Netlogon";
rpc_svc_name["12345678-1234-abcd-ef00-01234567cffb"] = "Net Logon service";
rpc_svc_pipes["8d9f4e40-a03d-11ce-8f69-08003e30051b"] = "ntsvcs";
rpc_svc_processes["8d9f4e40-a03d-11ce-8f69-08003e30051b"] = "services.exe";
rpc_svc_name["8d9f4e40-a03d-11ce-8f69-08003e30051b"] = "Plug and Play service";
rpc_svc_pipes["d335b8f6-cb31-11d0-b0f9-006097ba4e54"] = "policyagent";
rpc_svc_processes["d335b8f6-cb31-11d0-b0f9-006097ba4e54"] = "PolicyAgent";
rpc_svc_name["d335b8f6-cb31-11d0-b0f9-006097ba4e54"] = "IPSEC Policy Agent (Windows 2000)";
rpc_svc_pipes["12345678-1234-abcd-ef00-0123456789ab"] = "ipsec";
rpc_svc_processes["12345678-1234-abcd-ef00-0123456789ab"] = "PolicyAgent";
rpc_svc_name["12345678-1234-abcd-ef00-0123456789ab"] = "IPsec Services";
rpc_svc_pipes["369ce4f0-0fdc-11d3-bde8-00c04f8eee78"] = "ProfMapApi";
rpc_svc_processes["369ce4f0-0fdc-11d3-bde8-00c04f8eee78"] = "winlogon.exe";
rpc_svc_name["369ce4f0-0fdc-11d3-bde8-00c04f8eee78"] = "Userenv";
rpc_svc_pipes["c9378ff1-16f7-11d0-a0b2-00aa0061426a"] = "protected_storage";
rpc_svc_processes["c9378ff1-16f7-11d0-a0b2-00aa0061426a"] = "lsass.exe";
rpc_svc_name["c9378ff1-16f7-11d0-a0b2-00aa0061426a"] = "Protected Storage";
rpc_svc_pipes["8f09f000-b7ed-11ce-bbd2-00001a181cad"] = "ROUTER";
rpc_svc_processes["8f09f000-b7ed-11ce-bbd2-00001a181cad"] = "mprdim.dll";
rpc_svc_name["8f09f000-b7ed-11ce-bbd2-00001a181cad"] = "Remote Access";
rpc_svc_pipes["12345778-1234-abcd-ef00-0123456789ac"] = "lsass";
rpc_svc_processes["12345778-1234-abcd-ef00-0123456789ac"] = "lsass.exe";
rpc_svc_name["12345778-1234-abcd-ef00-0123456789ac"] = "SAM access";
rpc_svc_pipes["93149ca2-973b-11d1-8c39-00c04fb984f9"] = "scerpc";
rpc_svc_processes["93149ca2-973b-11d1-8c39-00c04fb984f9"] = "services.exe";
rpc_svc_name["93149ca2-973b-11d1-8c39-00c04fb984f9"] = "Security Configuration Editor (SCE)";
rpc_svc_pipes["12b81e99-f207-4a4c-85d3-77b42f76fd14"] = "SECLOGON";
rpc_svc_processes["12b81e99-f207-4a4c-85d3-77b42f76fd14"] = "seclogon";
rpc_svc_name["12b81e99-f207-4a4c-85d3-77b42f76fd14"] = "Secondary logon service";
rpc_svc_pipes["83da7c00-e84f-11d2-9807-00c04f8ec850"] = "SfcApi";
rpc_svc_processes["83da7c00-e84f-11d2-9807-00c04f8ec850"] = "winlogon.exe";
rpc_svc_name["83da7c00-e84f-11d2-9807-00c04f8ec850"] = "Windows File Protection";
rpc_svc_pipes["12345678-1234-abcd-ef00-0123456789ab"] = "spoolss";
rpc_svc_processes["12345678-1234-abcd-ef00-0123456789ab"] = "spoolsv.exe";
rpc_svc_name["12345678-1234-abcd-ef00-0123456789ab"] = "Spooler service";
rpc_svc_pipes["4b324fc8-1670-01d3-1278-5a47bf6ee188"] = "ntsvcs";
rpc_svc_processes["4b324fc8-1670-01d3-1278-5a47bf6ee188"] = "lsass.exe";
rpc_svc_name["4b324fc8-1670-01d3-1278-5a47bf6ee188"] = "Server service";
rpc_svc_pipes["4b112204-0e19-11d3-b42b-0000f81feb9f"] = "ssdpsrv";
rpc_svc_processes["4b112204-0e19-11d3-b42b-0000f81feb9f"] = "ssdpsrv";
rpc_svc_name["4b112204-0e19-11d3-b42b-0000f81feb9f"] = "SSDP service";
rpc_svc_pipes["367aeb81-9844-35f1-ad32-98f038001003"] = "ntsvcs";
rpc_svc_processes["367aeb81-9844-35f1-ad32-98f038001003"] = "services.exe";
rpc_svc_name["367aeb81-9844-35f1-ad32-98f038001003"] = "Services control manager";
rpc_svc_pipes["2f5f6520-ca46-1067-b319-00dd010662da"] = "tapsrv";
rpc_svc_processes["2f5f6520-ca46-1067-b319-00dd010662da"] = "Tapisrv";
rpc_svc_name["2f5f6520-ca46-1067-b319-00dd010662da"] = "Telephony service";
rpc_svc_pipes["300f3532-38cc-11d0-a3f0-0020af6b0add"] = "trkwks";
rpc_svc_processes["300f3532-38cc-11d0-a3f0-0020af6b0add"] = "Trkwks";
rpc_svc_name["300f3532-38cc-11d0-a3f0-0020af6b0add"] = "Distributed Link Tracking Client";
rpc_svc_pipes["8fb6d884-2388-11d0-8c35-00c04fda2795"] = "ntsvcs";
rpc_svc_processes["8fb6d884-2388-11d0-8c35-00c04fda2795"] = "w32time";
rpc_svc_name["8fb6d884-2388-11d0-8c35-00c04fda2795"] = "Windows Time (Windows 2000 and XP)";
rpc_svc_pipes["8fb6d884-2388-11d0-8c35-00c04fda2795"] = "W32TIME_ALT";
rpc_svc_processes["8fb6d884-2388-11d0-8c35-00c04fda2795"] = "w32time";
rpc_svc_name["8fb6d884-2388-11d0-8c35-00c04fda2795"] = "Windows Time (Windows Server 2003)";
rpc_svc_pipes["a002b3a0-c9b7-11d1-ae88-0080c75e4ec1"] = "winlogonrpc";
rpc_svc_processes["a002b3a0-c9b7-11d1-ae88-0080c75e4ec1"] = "winlogon.exe";
rpc_svc_name["a002b3a0-c9b7-11d1-ae88-0080c75e4ec1"] = "Winlogon";
rpc_svc_pipes["338cd001-2244-31f1-aaaa-900038001003"] = "winreg";
rpc_svc_processes["338cd001-2244-31f1-aaaa-900038001003"] = "RemoteRegistry";
rpc_svc_name["338cd001-2244-31f1-aaaa-900038001003"] = "Remote registry service";
rpc_svc_pipes["45f52c28-7f9f-101a-b52b-08002b2efabe"] = "winspipe";
rpc_svc_processes["45f52c28-7f9f-101a-b52b-08002b2efabe"] = "wins.exe";
rpc_svc_name["45f52c28-7f9f-101a-b52b-08002b2efabe"] = "WINS service";
rpc_svc_pipes["6bffd098-a112-3610-9833-46c3f87e345a"] = "ntsvcs";
rpc_svc_processes["6bffd098-a112-3610-9833-46c3f87e345a"] = "lsass.exe";
rpc_svc_name["6bffd098-a112-3610-9833-46c3f87e345a"] = "Workstation service";

#---------------------------------------------------------------------#

#
# String from a buffer. Inverts the bytes.
#

function istring_from_buffer( b, start, end ) {

  local_var b, start, end, __ret, __i, __hx;

  __ret = "";

  for( __i = start; __i <= end; __i++ ) {
    __hx = hex( ord( b[__i] ) );
    __hx = __hx - string( "0x" );
    # ouch, would drop zeros without string
    __ret = string( __hx, __ret );
  }
  return( __ret );
}

#
# String from a buffer. Straight.
#

function string_from_buffer( b, start, end ) {

  local_var b, start, end, __ret, __i, __hx;

  __ret = "";

  for( __i = start; __i <= end; __i++ ) {
    __hx = hex( ord( b[__i] ) );
    __hx = __hx - string( "0x" );
    # ouch, would drop zeros without string
    __ret = string( __ret, __hx );
  }
  return( __ret );
}

#
# Return the GUID/UUID as something printable
#
# Binary format of UUIDs is as follows:
#   4 bytes  TL (time low)
#   2 bytes  TM (time middle)
#   2 bytes  TH (time high + version)
#   1 byte   CH (clock seq high + reserved)
#   1 byte   CL (clock seq low)
#   6 bytes  NI (node id)
# TL, TM, and TH are interpreted as little endian numbers...
# or (surprise) as big endian numbers depending on the endianness flag
# in PDU header, the location in PDU (header, body), the phase of moon
# and other things; internally, we use LE format.
#
# Text format is as follows:
#   TL-TM-TH-CHCL-NI[0]NI[1]..NI[5]
# where all values are formatted as zero-padded base-16 numbers.
#

function struuid( uuid ) {

  local_var uuid, _bTL, _bTM, _bTH, _bCx, _bNI;

  _bTL = istring_from_buffer( b:uuid, start:0, end:3 );
  _bTM = istring_from_buffer( b:uuid, start:4, end:5 );
  _bTH = istring_from_buffer( b:uuid, start:6, end:7 );
  _bCx = string_from_buffer( b:uuid, start:8, end:9 );
  _bNI = string_from_buffer( b:uuid, start:10, end:15 );
  return( _bTL + "-" + _bTM + "-" + _bTH + "-" + _bCx + "-" + _bNI );
}

#
# Prepare DCE BIND request
#

function dce_bind() {

  local_var ep_uuid, ep_vers, ts_uuid, ts_vers, req_hdr;

  # Endpoint mapper UUID:
  #   E1AF8308-5D1F-11C9-91A4-08002B14A0FA
  ep_uuid = raw_string( 0x08, 0x83, 0xAF, 0xE1, 0x1F, 0x5D, 0xC9, 0x11,
                        0x91, 0xA4, 0x08, 0x00, 0x2B, 0x14 ,0xA0, 0xFA );
  ep_vers = raw_string( 0x03, 0x00, 0x00, 0x00 );

  # Transfer syntar UUID:
  #   8A885D04-1CEB-11C9-9FE8-08002B104860
  ts_uuid = raw_string( 0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11,
                        0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60 );
  ts_vers = raw_string( 0x02, 0x00, 0x00, 0x00 );

  # Request header
  req_hdr = raw_string( 0x05, 0x00,              # version, minor version
                        0x0b, 0x00,              # BINDPACKET, flags
                        0x10, 0x00, 0x00, 0x00,  # data representation
                        0x48, 0x00,              # fragment length
                        0x00, 0x00,              # auth length
                        0x01, 0x00, 0x00, 0x00,  # call id
                        0x00, 0x10, 0x00, 0x10,  # max xmit frag, max recv frag
                        0x00, 0x00, 0x00, 0x00,  # assoc group
                        0x01,                    # num ctx items
                        0x00, 0x00, 0x00,        # (padding)
                        0x00, 0x00,              # p_cont_id
                        0x01,                    # n_transfer_syn
                        0x00 );                  # (padding)

  return( string( req_hdr, ep_uuid, ep_vers, ts_uuid, ts_vers ) );
}

#
# Prepare Endpoint Mapper enumeration request
#

function dce_enum_get_next( callid, handle ) {

  local_var callid, handle, _c0, req_hdr, req_tlr;

  _c0 = callid % 255;

  # Request header
  req_hdr = raw_string( 0x05, 0x00,               # version, minor version
                        0x00, 0x03,               # REQUESTPACKET, flags
                        0x10, 0x00, 0x00, 0x00,   # data representation
                        0x40, 0x00,               # fragment length
                        0x00, 0x00,               # auth length
                        _c0,  0x00, 0x00, 0x00,   # call id
                        0x00, 0x00, 0x00, 0x00,   # alloc hint
                        0x00, 0x00,               # context id
                        0x02, 0x00,               # opnum: EPT_LOOKUP
                        0x00, 0x00, 0x00, 0x00,   # inquiry_type: RPC_C_EP_ALL_ELTS
                        0x00, 0x00, 0x00, 0x00,   # object
                        0x00, 0x00, 0x00, 0x00,   # interface_id
                        0x00, 0x00, 0x00, 0x00,   # vers_option
                        0x00, 0x00, 0x00, 0x00 ); # entry_handle.attributes

  # Request trailer
  req_tlr = raw_string( 0x01, 0x00, 0x00, 0x00 ); # max_ents

  return( string( req_hdr, handle, req_tlr ) );
}

#
# Extract integer values from buffers
#
# These functions should be NASL builtins... :(
#

global_var little_endian;
little_endian = TRUE;

function load_long( b, t ) {

  # little_endian is global
  local_var b, t, __ret_lo_lo, __ret_hi_lo, __ret_lo_hi, __ret_hi_hi, __ret;

  if( little_endian ) {
    __ret_lo_lo = ord( b[t] );
    __ret_hi_lo = ord( b[t+1] ) * 256;
    __ret_lo_hi = ord( b[t+2] ) * 65536;
    __ret_hi_hi = ord( b[t+3] ) * 16777216;
  } else {
    __ret_lo_lo = ord( b[t+3] );
    __ret_hi_lo = ord( b[t+2] ) * 256;
    __ret_lo_hi = ord( b[t+1] ) * 65536;
    __ret_hi_hi = ord( b[t] ) * 16777216;
  }
  __ret = __ret_hi_hi + __ret_lo_hi + __ret_hi_lo + __ret_lo_lo;
  return( __ret );
}

function load_short( b, t ) {

  # little_endian is global
  local_var b, t, __ret_lo, __ret_hi, __ret;

  if( little_endian ) {
    __ret_lo = ord( b[t] );
    __ret_hi = ord( b[t+1] ) * 256;
  } else {
    __ret_lo = ord( b[t+1] );
    __ret_hi = ord( b[t] ) * 256;
  }
  __ret = __ret_hi + __ret_lo;
  return( __ret );
}

function load_short_le( b, t ) {

  local_var b, t, __ret_lo, __ret_hi, __ret;

  __ret_lo = ord( b[t] );
  __ret_hi = ord( b[t+1] ) * 256;
  __ret = __ret_hi + __ret_lo;
  return( __ret );
}

function load_short_be( b, t ) {

  local_var b, t, __ret_lo, __ret_hi, __ret;

  __ret_lo = ord( b[t+1] );
  __ret_hi = ord( b[t] ) * 256;
  __ret = __ret_hi + __ret_lo;
  return( __ret );
}

#
# Extract UUID from buffer
#

function load_uuid_le( b, t ) {

  local_var b, t, __ret, __i;

  __ret = "";

  for( __i = 0; __i < 16; __i++ ) {
    # ouch, would drop zero bytes without raw_string
    __ret = string( __ret, raw_string( ord( b[t + __i] ) ) );
  }
  return( __ret );
}

function load_uuid( b, t ) {

  # little_endian is global
  local_var b, t, __ret, __i;

  __ret = "";

  if( little_endian ) {
    __ret = load_uuid_le( b:b, t:t );
  } else {
    __ret = string( __ret,
                    raw_string( ord( b[t + 3] ) ), raw_string( ord( b[t + 2] ) ),
                    raw_string( ord( b[t + 1] ) ), raw_string( ord( b[t] ) ),
                    raw_string( ord( b[t + 5] ) ), raw_string( ord( b[t + 4] ) ),
                    raw_string( ord( b[t + 7] ) ), raw_string( ord( b[t + 6] ) ) );
    for( __i = 8; __i < 16; __i++ ) {
      __ret = string( __ret, raw_string( ord( b[t + __i] ) ) );
    }
  }
  return( __ret );
}

#
# Extract string from buffer
# Unprintable characters are replaced with ?
#

function load_string( b, t, l ) {

  local_var b, t, l, __ret, __i, __c;

  __ret = "";

  for( __i = 0; __i < l; __i++ ) {
    __c = ord( b[t + __i] );
    if( __c == 0 ) return( __ret );
    if( ( __c < 32 ) || ( __c > 127 ) ) {
      __ret = string( __ret, "?" );
    } else {
      __ret = string( __ret, raw_string( __c ) );
    }
  }
  return( __ret) ;
}

#
# Parse a response to an enumeration request
#

function dce_parse( result ) {

  # handle is global_var
  local_var result, hndatr, p, tint, floors, guid;
  local_var majver, proto, ncaproto, ncahost, ncaport, ncaunk;
  local_var annotation, floor, addr_type, addr_data, decoded;

  # nb: RESPONSEPACKET
  if( ord( result[2] ) != 0x02 ) {
    return( -1 );
  }

  # Update the context handle
  hndatr = load_long( b:result, t:24 );
  handle = load_uuid( b:result, t:28 );

  # Skip:
  #   common DCE header (16 bytes)
  #   alloc_hint, p_cont_id, cancel_count, padding (8 bytes)
  #   context_handle.attributes (4 bytes)
  #   context_handle.uuid (16 bytes)
  #   num_elts (4 bytes) (should check != 0?)
  #   "something" (36 bytes)
  p = 84;

  # Annotation
  tint = load_long( b:result, t:p );
  p += 4;
  if( tint > 64 ) {
    return( -1 );
  }
  annotation = load_string( b:result, t:p, l:tint );
  p += tint;
  while( p % 4 != 0 ) p += 1;

  # Skip tower lengths
  p += 8;

  # Number of floors
  floors = load_short_le( b:result, t:p );
  p += 2;

  guid = "";
  majver = "???";
  proto = "???";
  ncaproto = "???";
  ncahost = "???";
  ncaport = "???";
  ncaunk = ""; # for undecoded floors

  # Analyze floors
  for( floor = 1; floor <= floors; floor++ ) {

    # Sanity check
    if( p >= strlen( result ) - 4 ) {
      return( -1 );
    }

    # Floor part #1 (protocol identifier)
    tint = load_short_le( b:result, t:p );
    p += 2;
    addr_type = ord( result[p] );
    addr_data = string_from_buffer( b:result, start:p + 1, end:p + tint - 2 );
    if( floor == 1 ) {
      # expecting addr_type == 0x0d (UUID_type_identifier), tint == 19
      guid = load_uuid_le( b:result, t:p + 1 );
      guid = struuid( uuid:guid );
      majver = load_short_le( b:result, t:p + 17 );
    }

    p += tint;

    # Floor part #2 (related information)
    tint = load_short_le( b:result, t:p );
    p += 2;
    # skip floors 1-3, expected contents:
    #   floor #1: interface UUID (see above)
    #   floor #2: transfer syntax UUID
    #   floor #3: RPC connection-oriented/connectionless
    if( floor > 3 ) {
      decoded = FALSE;
      if( addr_type == 0x01 ) {
        # nonstandard NetBIOS name (string)
        ncahost = "{0x01}" + load_string( b:result, t:p, l:tint );
        decoded = TRUE;
      }
      if( addr_type == 0x07 ) {
        # TCP port (2 bytes)
        proto = "tcp";
        ncaproto = "ncacn_ip_tcp:";
        ncaport = load_short_be( b:result, t:p );
        decoded = TRUE;
      }
      if( addr_type == 0x08 ) {
        # UDP port (2 bytes)
        proto = "udp";
        ncaproto = "ncadg_ip_udp:";
        ncaport = load_short_be( b:result, t:p );
        decoded = TRUE;
      }
      if( addr_type == 0x09 ) {
        # IP address (4 bytes)
        ncahost = string( ord( result[p] ), ".", ord( result[p+1] ), ".",
                          ord( result[p+2]) , ".", ord( result[p+3] ) );
        decoded = TRUE;
      }
      if( addr_type == 0x0f ) {
        # named pipe path (string)
        proto = "PIPE";
        ncaproto = "ncacn_np:";
        ncaport = load_string( b:result, t:p, l:tint );
        decoded = TRUE;
      }
      if( addr_type == 0x10 ) {
        # LRPC port (string)
        proto = "LRPC";
        ncaproto = "ncalrpc";
        ncahost = "";
        ncaport = load_string( b:result, t:p, l:tint );
        decoded = TRUE;
      }
      if( addr_type == 0x11 ) {
        # NetBIOS name (string)
        ncahost = load_string( b:result, t:p, l:tint );
        decoded = TRUE;
      }
      if( addr_type == 0x16 ) {
        # Appletalk DSP port (string)
        proto = "APPLE-DSP";
        ncaproto = "ncacn_at_dsp";
        ncaport = load_string( b:result, t:p, l:tint );
        decoded = TRUE;
      }
      if( addr_type == 0x17 ) {
        # Appletalk DDP port (string?)
        proto = "APPLE-DDP";
        ncaproto = "ncadg_at_ddp";
        ncaport = load_string( b:result, t:p, l:tint );
        decoded = TRUE;
      }
      if( addr_type == 0x18 ) {
        # Appletalk name (string)
        ncahost = load_string( b:result, t:p, l:tint );
        decoded = TRUE;
      }
      if( addr_type == 0x1f ) {
        # HTTP port (2 bytes)
        proto = "tcp";
        ncaproto = "ncacn_http:";
        ncaport = load_short_be( b:result, t:p );
        decoded = TRUE;
      }
      # seen in the wild, to be identified:
      # - 0x0c (2 bytes)    broken IPX?
      # - 0x0d (10 bytes)   broken IPX? (collision with UUID)
      if( ! decoded ) {
        ncaunk = string( ncaunk, "{", hex( addr_type ), "}", addr_data, ":",
                         string_from_buffer( b:result, start:p, end:p+tint-1 ) );
      }
    }
    p += tint;
  }

  # Found a service
  if( guid ) {
    report += "     UUID: " + guid + ", version " + majver + '\n';
    if( proto != "???" )
      report += "     Endpoint: " + ncaproto + ncahost + "[" + ncaport + ']\n';
    if( ncaunk )
      report += "     Undecoded endpoint data: " + ncaunk + '\n';
    if( annotation )
      report += "     Annotation: " + annotation + '\n';
    if( rpc_svc_pipes[guid] )
      report += "     Named pipe : " + rpc_svc_pipes[guid] + '\n';
    if( rpc_svc_processes[guid] )
      report += "     Win32 service or process : " + rpc_svc_processes[guid] + '\n';
    if( rpc_svc_name[guid] )
      report += "     Description : " + rpc_svc_name[guid] + '\n';

    if( ( proto == "udp" ) || ( proto == "tcp" ) ) {
      if( proto == "tcp" ) {
        if( get_port_state( ncaport ) && ! in_array( search:ncaport, array:tcp_services_list ) ) {
          tcp_services_list = make_list( tcp_services_list, ncaport );
          register_service( port:ncaport, proto:"msrpc", ipproto:"tcp", message:"A DCE/RPC or MSRPC service seems to be running on this port" );
        }
        set_kb_item( name:"dcetest/" + port + "/enumerated/tcp/ports", value:ncaport );
        set_kb_item( name:"dcetest/" + port + "/enumerated/tcp/" + ncaport + "/report", value:report );
      } else {
        if( get_udp_port_state( ncaport ) && ! in_array( search:ncaport, array:udp_services_list ) ) {
          udp_services_list = make_list( udp_services_list, ncaport );
          register_service( port:ncaport, proto:"msrpc", ipproto:"udp", message:"A DCE/RPC or MSRPC service seems to be running on this port" );
        }
        set_kb_item( name:"dcetest/" + port + "/enumerated/udp/ports", value:ncaport );
        set_kb_item( name:"dcetest/" + port + "/enumerated/udp/" + ncaport, value:report );
      }
    } else {
      set_kb_item( name:"dcetest/" + port + "/enumerated/noport/report", value:report );
    }
    return 1;
  }
  return 0;
}

#
# Receive a DCE message
# this is much faster than recv(..., length:4096)
#

function read_dce_pdu( sock ) {

  # little_endian is global
  local_var sock, __r0, __r1len, __r, __i;

  # Read response header
  __r0 = recv( socket:sock, length:16 );

  if( strlen( __r0 ) != 16 ) {
    return( "" );
  }

  if( ord( __r0[4] ) & 0xF0 == 0x10 ) {
    little_endian = TRUE;
  } else {
    little_endian = FALSE;
  }

  # Extract fragment length and read the rest
  __r1len = load_short( b:__r0, t:8 ) - 16;
  __r1 = recv( socket:sock, length:__r1len );

  if( strlen( __r1 ) != __r1len ) {
    return( "" );
  }

  # Concatenate the results...the safe way
  __r = "";
  for( __i = 0; __i < 16; __i++ )
    __r = string( __r, raw_string( ord( __r0[__i] ) ) );

  for( __i = 0; __i < __r1len; __i++ )
    __r = string( __r, raw_string( ord( __r1[__i] ) ) );

  return( __r );
}


#---------------------------------------------------------------------#

#
# The main program
#

zero_handle = raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
global_var handle;
handle = zero_handle;

port = 135;
if( ! get_port_state( port ) ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

enum = FALSE;

send( socket:soc, data:dce_bind() );
r = read_dce_pdu( sock:soc );
if( strlen( r ) < 60 ) {  # bad reply length
  close( soc );
  exit( 0 );
}

log_message( port:port, data:"A DCE endpoint resolution service seems to be running on this port." );
register_service( port:port, proto:"epmap", message:"A DCE endpoint resolution service seems to be running on this port." );

# Assume Windows if such an endpoint is detected
register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:"DCE/RPC and MSRPC Services Enumeration", port:port, desc:"DCE/RPC and MSRPC Services Enumeration", runs_key:"windows" );

for( x = 0; x < 4096; x++ ) {

  send( socket:soc, data:dce_enum_get_next( callid:x, handle:handle ) );
  r = read_dce_pdu( sock:soc );
  if( strlen( r ) <= 65 ) {
    # finished
    x = 4096;
  } else {
    dce_parse( result:r );
    enum = TRUE;
    if( handle == zero_handle ) {
      # finished
      x = 4096;
    }
  }
}

close( soc );

if( enum ) {
  set_kb_item( name:"dcetest/enumerated", value:TRUE );
  set_kb_item( name:"dcetest/" + port + "/enumerated", value:TRUE );
}

exit( 0 );

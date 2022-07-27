###################################################################
# OpenVAS Vulnerability Test
# $Id: smb_enum_services.nasl 11285 2018-09-07 09:40:40Z cfischer $
#
# SMB Enumerate Services
#
# LSS-NVT-2010-001
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Copyright (C) 2010 LSS <http://www.lss.hr>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.
###################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102016");
  script_version("$Revision: 11285 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:40:40 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2010-02-10 12:17:39 +0100 (Wed, 10 Feb 2010)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SMB Enumerate Services");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright(C) 2010 LSS");
  script_family("Windows");
  script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_nativelanman.nasl", "os_detection.nasl");
  script_require_ports(139, 445);
  script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("SMB/samba");

  script_tag(name:"solution", value:"To prevent access to the services and drivers
  list, you should either have tight login restrictions,
  so that only trusted users can access your host, and/or you
  should filter incoming traffic to this port.");

  script_tag(name:"impact", value:"An attacker may use this feature to gain better
  knowledge of the remote host.");

  script_tag(name:"summary", value:"This plugin implements the SvcOpenSCManager() and
  SvcEnumServices() calls to obtain the list of active and inactive
  services and drivers of the remote host, using the MS-DCE/RPC
  protocol over SMB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");

if( kb_smb_is_samba() ) exit( 0 );

#--------------------------------------------------------#
# Decodes the data sent back by svcenumservicesstatus()  #
#--------------------------------------------------------#
function svc_decode( data ) {

  local_var data, sz, i, len, num_svc, ret, off, j, off2;
  local_var name, svc, k;

  # ret = '';
  sz = '';
  if( strlen( data ) < 128 ) return FALSE;

  for( i = 4; i > 0; i-- ) {
    sz = sz * 256;
    sz = sz + ord( data[123+i] );
  }

  len = strlen( data );
  num_svc = ord( data[len-15] );
  num_svc = num_svc * 256;
  num_svc = num_svc + ord( data[len-16] );

  if( ! num_svc ) return FALSE;

  ret[0] = num_svc; # number of 'services'(services, drivers, processes)

  off = 0;
  lim = num_svc * 0x24;

  for( j = 0; j < lim; j += 0x24 ) {
    for( i = 4; i > 0; i-- ) {
      off = off * 256;
      off += ord( data[87+i+j] );
    }

    off2 = 0;
    for( i = 4; i > 0; i-- ) {
      off2 = off2 * 256;
      off2 += ord( data[91+i+j] );
    }

    # This fixes a "requesting character after end of string data"
    # as both offsets where not always an int
    off2 = int( off2 );
    off = int( off );

    if( off2 > strlen( data ) ) return(0);
    if( off > strlen( data ) ) return(0);

    name = '';
    svc = '';
    for( k = 0; k < 255; k++ ) {
      if( ! ( ord( data[off2+k+88] ) ) )
        k = 255;
      else
        name = string( name, raw_string( ord( data[off2+k+88] ) ) );
    }

    for( k = 0; k < 255; k++ ) {
      if( ! ( ord( data[off+k+88] ) ) )
        k = 255;
      else
        svc = string( svc, raw_string( ord( data[off+k+88] ) ) );
    }

    ret[1] = ret[1] + string( name, ' [', svc, ']\n' );
  }
  return ret;
}

#------------------------------------------------------#
# Obtains a handle we use in svcenumservicesstatus()   #
#------------------------------------------------------#
function svcopenscmanager( soc, name, uid, tid, pipe ) {

  # g_mhi and g_mlo are global vars from smb_nt.inc

  local_var soc, name, uid, tid, pipe;
  local_var tid_low, tid_high, uid_low, uid_high, pipe_low, pipe_high;
  local_var req, r, len, add, tot_len, tot_len_lo, bcc, bcc_lo, bcc_hi;
  local_var tot_hi, tot_lo, len2, len2_lo, len2_hi, len_lo, len_hi, hdl;

  tid_low = tid % 256;
  tid_high = tid / 256;
  uid_low = uid % 256;
  uid_high = uid / 256;
  pipe_low = pipe % 256;
  pipe_high = pipe / 256;

  req = raw_string( 0x00, 0x00, 0x00, 0x9c, 0xFF, 0x53, 0x4D, 0x42,
                    0x25, 0x00, 0x00, 0x00, 0x00, 0x18, 0x03, 0x80,
                    0x59, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, tid_low, tid_high, 0x00, 0x28,
                    uid_low, uid_high, g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x48,
                    0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x54, 0x00, 0x48, 0x00, 0x54, 0x00, 0x02,
                    0x00, 0x26, 0x00, pipe_low, pipe_high, 0x59, 0x00, 0x00,
                    0x5C, 0x00, 0x50, 0x00, 0x49, 0x00, 0x50, 0x00,
                    0x45, 0x00, 0x5C, 0x00, 0x00, 0x00, 0x00, 0x14,
                    0x05, 0x00, 0x0B, 0x00, 0x10, 0x00, 0x00, 0x00,
                    0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x30, 0x16, 0x30, 0x16, 0x00, 0x00, 0x00, 0x00,
                    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                    0x81, 0xBB, 0x7A, 0x36, 0x44, 0x98, 0xF1, 0x35,
                    0xAD, 0x32, 0x98, 0xF0, 0x38, 0x00, 0x10, 0x03,
                    0x02, 0x00, 0x00, 0x00, 0x04, 0x5D, 0x88, 0x8A,
                    0xEB, 0x1C, 0xC9, 0x11, 0x9F, 0xE8, 0x08, 0x00,
                    0x2B, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00 );

  send( socket:soc, data:req );
  r = smb_recv(socket:soc);
  if( ! r ) return FALSE;

  len = strlen( name );
  add = 4 - ( ( len + 1 ) % 4 );

  tot_len = 133 + len + add;
  tot_len_lo = tot_len % 256;
  tot_len_hi = tot_len / 256;

  bcc = 66 + len + add;
  bcc_lo = bcc % 256;
  bcc_hi = bcc / 256;
  tot = 49 + len + add ;
  tot_hi = tot/256;
  tot_lo = tot%256;

  len2 = 25 + len + add;
  len2_lo = len2 % 256;
  len2_hi = len2 / 256;

  len    = len + 1;
  len_lo = len % 256;
  len_hi = len / 256;

  req = raw_string( 0x00, 0x00, tot_len_hi, tot_len_lo, 0xFF, 0x53, 0x4D, 0x42,
                    0x25, 0x00, 0x00, 0x00, 0x00, 0x18, 0x03, 0x80,
                    0x63, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, tid_low, tid_high, 0x00, 0x28,
                    uid_low, uid_high, g_mlo, g_mhi, 0x10, 0x00, 0x00, tot_lo,
                    tot_hi, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x54, 0x00, tot_lo, tot_hi, 0x54, 0x00, 0x02,
                    0x00, 0x26, 0x00, pipe_low, pipe_high, bcc_lo, bcc_hi, 0x00, 0x5C,
                    0x00, 0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45,
                    0x00, 0x5C, 0x00, 0x00, 0x00, 0x00, 0x5C, 0x05,
                    0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00, tot_lo,
                    tot_hi, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, len2_lo,
                    len2_hi, 0x00, 0x00, 0x00, 0x00, 0x1B, 0x00, 0x60,
                    0x02, 0x7D, 0x00, len_lo, len_hi, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, len_lo, len_hi, 0x00, 0x00 ) +
        tolower( name ) + raw_string( 0 );

  # req = req + raw_string(0x00);
  # else req = req + raw_string(0x00, 0x00);
  if( add ) {
    req += crap( data:raw_string(0), length:add );
  }

  req += raw_string( 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00 );

  send( socket:soc, data:req );
  r = smb_recv( socket:soc );
  if( ! r ) return FALSE;
  #if( strlen( r ) < 100 ) return FALSE;
  if( strlen( r ) < 104 ) return FALSE;

  # extract the handle
  hdl = '';
  for( i = 0; i < 21; i++ ) {
    hdl = string( hdl, raw_string( ord( r[83+i] ) ) );
  }
  return hdl;
}

#------------------------------------------------#
# creates a valid smbreadx() request             #
#------------------------------------------------#
function smbreadx( tid_low, tid_high, uid_low, uid_high, pipe_low, pipe_high ) {

  local_var tid_low, tid_high, uid_low, uid_high, pipe_low, pipe_high;

  return( raw_string( 0x00, 0x00, 0x00, 0x3C, 0xFF, 0x53, 0x4D, 0x42,
                      0x2E, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x80,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, tid_low, tid_high, 0x00, 0x28,
                      uid_low, uid_high, g_mlo, g_mhi, 0x0C, 0xFF, 0x00, 0x00,
                      0x00, pipe_low, pipe_high, 0x00, 0x00, 0x00, 0x00, 0xFF,
                      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                      0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 ) );
}

#----------------------------------------------#
# returns TRUE if svcenumservicesstatus needs  #
# to call smbreadx() to get the rest of the    #
# services list                                #
#----------------------------------------------#
function moredata( data ) {

  local_var data, len_data, start, _i;

  if( ! data ) return FALSE;

  len_data = strlen( data );
  start = len_data - 4;
  for( _i = start; _i < len_data; _i++ ) {
    if( ord( data[_i] ) ) return TRUE;
  }
  return FALSE;
}

# svcenumservicesstatus global constants
SERVICE_STATE_ACTIVE              = raw_string(0x01, 0x00, 0x00, 0x00);
SERVICE_STATE_INACTIVE            = raw_string(0x02, 0x00, 0x00, 0x00);
SERVICE_STATE_ALL                 = raw_string(0x03, 0x00, 0x00, 0x00);#( SERVICE_STATE_ACTIVE | SERVICE_STATE_INACTIVE )
SERVICE_TYPE_KERNEL_DRIVER        = raw_string(0x01, 0x00, 0x00, 0x00);
SERVICE_TYPE_FS_DRIVER            = raw_string(0x02, 0x00, 0x00, 0x00);
SERVICE_TYPE_ADAPTER              = raw_string(0x04, 0x00, 0x00, 0x00);#couldn't get to work
SERVICE_TYPE_RECOGNIZER_DRIVER    = raw_string(0x08, 0x00, 0x00, 0x00);#couldn't get to work
SERVICE_TYPE_DRIVER               = raw_string(0x0F, 0x00, 0x00, 0x00);#(SERVICE_TYPE_KERNEL_DRIVER|SERVICE_TYPE_FS_DRIVER|SERVICE_TYPE_RECOGNIZER_DRIVER
SERVICE_TYPE_WIN32_OWN_PROCESS    = raw_string(0x10, 0x00, 0x00, 0x00);
SERVICE_TYPE_WIN32_SHARE_PROCESS  = raw_string(0x20, 0x00, 0x00, 0x00);
SERVICE_TYPE_WIN32                = raw_string(0x30, 0x00, 0x00, 0x00);#SERVICE_TYPE_WIN32_OWN_PROCESS|SERVICE_TYPE_WIN32_SHARE_PROCESS
SERVICE_TYPE_INTERACTIVE_PROCESS  = raw_string(0x00, 0x01, 0x00, 0x00);#0x100;

#----------------------------------------------#
# svcenumservicesstatus() :                    #
# This function makes the appropriate calls    #
# to get the list of the remote active services#
# and decodes the result. It returns FALSE if  #
# no service is running at all.                #
#----------------------------------------------#
function svcenumservicesstatus( soc, name, uid, tid, pipe, handle, svc_type, svc_state ) {

  # g_mhi and g_mlo are global vars from smb_nt.inc

  local_var soc, name, uid, tid, pipe, handle, svc_type, svc_state;
  local_var tid_low, tid_high, uid_low, uid_high, pipe_low, pipe_high;
  local_var req, r, len, i, r2, len_r2, k, ret;

  tid_low = tid % 256;
  tid_high = tid / 256;
  uid_low = uid % 256;
  uid_high = uid / 256;
  pipe_low = pipe % 256;
  pipe_high = pipe / 256;

  # We make a first call to svcenumservicesstatus(), and we declare
  # our buffer size as being 0 bytes. We receive an error with the
  # amount of bytes we'd need, then we make a second request
  # with that value.

  # First request
  req = raw_string( 0x00, 0x00, 0x00, 0x94, 0xFF, 0x53, 0x4D, 0x42,
                    0x25, 0x00, 0x00, 0x00, 0x00, 0x18, 0x03, 0x80,
                    0x6B, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, tid_low, tid_high, 0x00, 0x28,
                    uid_low, uid_high, g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x40,
                    0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x54, 0x00, 0x40, 0x00, 0x54, 0x00, 0x02,
                    0x00, 0x26, 0x00, pipe_low, pipe_high, 0x51, 0x00, 0x00,
                    0x5C, 0x00, 0x50, 0x00, 0x49, 0x00, 0x50, 0x00,
                    0x45, 0x00, 0x5C, 0x00, 0x00, 0x00, 0x00, 0x88,
                    0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
                    0x40, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
                    0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1A ) + handle +
        svc_type + svc_state + raw_string( 0x24, 0x00, 0x00, 0x00, 0x74, 0xFF,
                    0x12, 0x00, 0x00, 0x00, 0x00, 0x00 );

  send( socket:soc, data:req );
  r = smb_recv( socket:soc );
  if( strlen( r ) < 128 ) return NULL;

  len = '';
  for( i = 124; i < 128; i++ )
    len = string( len, raw_string( ord( r[i] ) ) );

  # Second request, with the appropriate length
  req = raw_string( 0x00, 0x00, 0x00, 0x94, 0xFF, 0x53, 0x4D, 0x42,
                    0x25, 0x00, 0x00, 0x00, 0x00, 0x18, 0x03, 0x80,
                    0x6B, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, tid_low, tid_high, 0x00, 0x28,
                    uid_low, uid_high, g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x40,
                    0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x54, 0x00, 0x40, 0x00, 0x54, 0x00, 0x02,
                    0x00, 0x26, 0x00, pipe_low, pipe_high, 0x51, 0x00, 0x00,
                    0x5C, 0x00, 0x50, 0x00, 0x49, 0x00, 0x50, 0x00,
                    0x45, 0x00, 0x5C, 0x00, 0x00, 0x00, 0x00, 0x88,
                    0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
                    0x40, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
                    0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1A ) + handle +
        svc_type + svc_state + len + raw_string( 0x74, 0xFF, 0x12, 0x00, 0x00,
                    0x00, 0x00, 0x00 );

  send( socket:soc, data:req );
  r = smb_recv( socket:soc );

  # nb: get what's left - smbreadX request
  if( ord( r[9] ) ) {
    req = smbreadx( tid_low:tid_low, tid_high:tid_high, uid_low:uid_low, uid_high:uid_high, pipe_low:pipe_low, pipe_high:pipe_high );
    send( socket:soc, data:req );
    r2 = smb_recv( socket:soc );

    # Merge the relevant portion of r2 into r
    len_r2 = strlen( r2 );
    for( k = 64; k < len_r2; k++ ) {
      r += raw_string( ord( r2[k] ) );
    }

    while( moredata( data:r2 ) ) {

      req = smbreadx( tid_low:tid_low, tid_high:tid_high, uid_low:uid_low, uid_high:uid_high, pipe_low:pipe_low, pipe_high:pipe_high );
      send( socket:soc, data:req );
      r2 = smb_recv( socket:soc );
      len_r2 = strlen( r2 );
      for( k = 88; k < len_r2; k++ ) {
        r += raw_string( ord( r2[k] ) );
      }
    }
  }

  if( ! ret = svc_decode( data:r ) ) return NULL;

  if( svc_state == SERVICE_STATE_ACTIVE ) {
    if( svc_type == SERVICE_TYPE_KERNEL_DRIVER ) {
      set_kb_item( name:"SMB/number_of_active_kernel_drivers", value:ret[0] );
      set_kb_item( name:"SMB/active_kernel_drivers", value:ret[1] );
    }
    if( svc_type == SERVICE_TYPE_FS_DRIVER ) {
      set_kb_item( name:"SMB/number_of_active_fs_drivers", value:ret[0] );
      set_kb_item( name:"SMB/active_fs_drivers", value:ret[1] );
    }
    if( svc_type == SERVICE_TYPE_ADAPTER ) {
      set_kb_item( name:"SMB/number_of_active_adapters", value:ret[0] );
      set_kb_item( name:"SMB/active_adapters", value:ret[1] );
    }
    if( svc_type == SERVICE_TYPE_RECOGNIZER_DRIVER ) {
      set_kb_item( name:"SMB/number_of_active_recognizer_drivers", value:ret[0] );
      set_kb_item( name:"SMB/active_recognizer_drivers", value:ret[1] );
    }
    if( svc_type == SERVICE_TYPE_DRIVER ) {
      set_kb_item( name:"SMB/number_of_active_drivers", value:ret[0] );
      set_kb_item( name:"SMB/active_drivers", value:ret[1] );
    }
    if( svc_type == SERVICE_TYPE_WIN32_OWN_PROCESS ) {
      set_kb_item( name:"SMB/number_of_active_win32_own_processes", value:ret[0] );
      set_kb_item( name:"SMB/active_win32_own_procesess", value:ret[1] );
    }
    if( svc_type == SERVICE_TYPE_WIN32_SHARE_PROCESS ) {
      set_kb_item( name:"SMB/number_of_active_win32_share_processes", value:ret[0] );
      set_kb_item( name:"SMB/active_win32_share_procesess", value:ret[1] );
    }
    if( svc_type == SERVICE_TYPE_WIN32 ) {
      set_kb_item( name:"SMB/number_of_active_win32_procesess", value:ret[0] );
      #TBD: Why is this commented out? set_kb_item( name:"SMB/active_win32_procesess", value:ret[1] )
      set_kb_item( name:"SMB/svcs", value:ret[1] ); #changed naming convention to "svcs" to accommodate dependencies
    }
    if( svc_type == SERVICE_TYPE_INTERACTIVE_PROCESS ) {
      set_kb_item( name:"SMB/number_of_active_interactive_processes", value:ret[0] );
      set_kb_item( name:"SMB/active_interactive_procesess", value:ret[1] );
    }
  } else if( svc_state == SERVICE_STATE_INACTIVE ) {
    if( svc_type == SERVICE_TYPE_KERNEL_DRIVER ) {
      set_kb_item( name:"SMB/number_of_inactive_kernel_drivers", value:ret[0] );
      set_kb_item( name:"SMB/inactive_kernel_drivers", value:ret[1] );
    }
    if( svc_type == SERVICE_TYPE_FS_DRIVER ) {
      set_kb_item( name:"SMB/number_of_inactive_fs_drivers", value:ret[0] );
      set_kb_item( name:"SMB/inactive_fs_drivers", value:ret[1] );
    }
    if( svc_type == SERVICE_TYPE_ADAPTER ) {
      set_kb_item( name:"SMB/number_of_inactive_adapters", value:ret[0] );
      set_kb_item( name:"SMB/inactive_adapters", value:ret[1] );
    }
    if( svc_type == SERVICE_TYPE_RECOGNIZER_DRIVER ) {
      set_kb_item( name:"SMB/number_of_inactive_recognizer_drivers", value:ret[0] );
      set_kb_item( name:"SMB/inactive_recognizer_drivers", value:ret[1] );
    }
    if( svc_type == SERVICE_TYPE_DRIVER ) {
      set_kb_item( name:"SMB/number_of_inactive_drivers", value:ret[0] );
      set_kb_item( name:"SMB/inactive_drivers", value:ret[1] );
    }
    if( svc_type == SERVICE_TYPE_WIN32_OWN_PROCESS ) {
      set_kb_item( name:"SMB/number_of_inactive_win32_own_processes", value:ret[0] );
      set_kb_item( name:"SMB/inactive_win32_own_procesess", value:ret[1] );
    }
    if( svc_type == SERVICE_TYPE_WIN32_SHARE_PROCESS ) {
      set_kb_item( name:"SMB/number_of_inactive_win32_share_processes", value:ret[0] );
      set_kb_item( name:"SMB/inactive_win32_share_procesess", value:ret[1] );
    }
    if( svc_type == SERVICE_TYPE_WIN32 ) {
      set_kb_item( name:"SMB/number_of_inactive_win32_procesess", value:ret[0] );
      set_kb_item( name:"SMB/inactive_win32_procesess", value:ret[1] );
    }
    if( svc_type == SERVICE_TYPE_INTERACTIVE_PROCESS ) {
      set_kb_item( name:"SMB/number_of_inactive_interactive_processes", value:ret[0] );
      set_kb_item( name:"SMB/inactive_interactive_procesess", value:ret[1] );
    }
  }
  return ret;
}

####################################
###########  MAIN  #################
####################################

port = kb_smb_transport();
if( ! port ) port = 139;
login = kb_smb_login();
domain = kb_smb_domain();
pass = kb_smb_password();
name = chomp( kb_smb_name() ); #TODO: check for a bug! kb_smb_name returned a name with trailing whitespace!


soc = open_sock_tcp( port );
if( ! soc ) {
  exit( 0 );
}

r = smb_session_request( soc:soc, remote:name );
if( ! r ) {
  close( soc );
  exit( 0 );
}

prot = smb_neg_prot( soc:soc );
if( ! prot ) {
  close( soc );
  exit( 0 );
}

##Validate length of response
if(strlen(prot) < 5 ) {
  exit(0);
}

##Currently Only SMB1 is supported, For SMB2 ord(prot[4]) == 254
if(ord(prot[4]) == 254)
{
  ##Close current Socket
  close(soc);
  ## Open a new Socket
  soc = open_sock_tcp(port);
  if(!soc){
   exit(0);
  }

  ##Session Request
  r = smb_session_request(soc:soc, remote:name);
  if(!r) { close(soc); exit(0); }

  ##nb: Try negotiating with SMB1
  prot = smb_neg_prot_NTLMv1(soc:soc);
  if(!prot)
  {
    close(soc);
    exit(0);
  }
}

r = smb_session_setup( soc:soc, login:login, password:pass, domain:domain, prot:prot );
if( ! r ) {
  close( soc );
  exit( 0 );
}

uid = session_extract_uid( reply:r );
if( ! uid ) {
  close( soc );
  exit( 0 );
}

r = smb_tconx( soc:soc, name:name, uid:uid, share:'IPC$' );
if( ! r ) {
  close( soc );
  exit( 0 );
}

tid = tconx_extract_tid( reply:r );
if( ! tid ) {
  close( soc );
  exit( 0 );
}

# Create a pipe to \svcctl
r = smbntcreatex( soc:soc, uid:uid, tid:tid, name:'\\svcctl' );
if( ! r ) {
  close( soc );
  exit( 0 );
}

# and extract its ID
pipe = smbntcreatex_extract_pipe( reply:r );
if( ! pipe ) {
  close( soc );
  exit( 0 );
}

# For the moment bind() is implemented in svcopenscmanager(). Due for implementation in msrpc.inc.
# dcerpc_bind(soc:soc, user_id:uid, tree_id:tid, fid:pipe);
handle = svcopenscmanager( soc:soc, name:name, uid:uid, tid:tid, pipe:pipe );
if( handle == FALSE ) {
  close( soc );
  exit( 0 );
}

#report_data = '';
report_data_separator = '\n\n##############################################\n\n';

services = svcenumservicesstatus( soc:soc, name:name, uid:uid, tid:tid, pipe:pipe, handle:handle, svc_type:SERVICE_TYPE_WIN32, svc_state:SERVICE_STATE_ACTIVE );
if( ! isnull( services ) ) {
  report_data += 'WIN32 active services: \n' + services[1];
  report_data += report_data_separator;
}

services = svcenumservicesstatus( soc:soc, name:name, uid:uid, tid:tid, pipe:pipe, handle:handle, svc_type:SERVICE_TYPE_WIN32, svc_state:SERVICE_STATE_INACTIVE );
if( ! isnull( services ) ) {
  report_data += 'WIN32 inactive services: \n' + services[1];
  report_data += report_data_separator;
}

services = svcenumservicesstatus( soc:soc, name:name, uid:uid, tid:tid, pipe:pipe, handle:handle, svc_type:SERVICE_TYPE_DRIVER, svc_state:SERVICE_STATE_ACTIVE );
if( ! isnull( services ) ) {
  report_data += 'WIN32 active drivers: \n' + services[1];
  report_data += report_data_separator;
}

services = svcenumservicesstatus( soc:soc, name:name, uid:uid, tid:tid, pipe:pipe, handle:handle, svc_type:SERVICE_TYPE_DRIVER, svc_state:SERVICE_STATE_INACTIVE );
if( ! isnull( services ) ) {
  report_data += 'WIN32 inactive drivers: \n' + services[1];
  report_data += report_data_separator;
}

services = svcenumservicesstatus( soc:soc, name:name, uid:uid, tid:tid, pipe:pipe, handle:handle, svc_type:SERVICE_TYPE_INTERACTIVE_PROCESS, svc_state:SERVICE_STATE_ACTIVE );
if( ! isnull( services ) ) {
  report_data += 'WIN32 active interactive services: \n' + services[1];
  report_data += report_data_separator;
}

services = svcenumservicesstatus( soc:soc, name:name, uid:uid, tid:tid, pipe:pipe, handle:handle, svc_type:SERVICE_TYPE_INTERACTIVE_PROCESS, svc_state:SERVICE_STATE_INACTIVE );
if( ! isnull( services ) ) {
  report_data += 'WIN32 inactive interactive services: \n' + services[1];
}

if( report_data ) {
  log_message( port:port, data:report_data );
}

close( soc );
exit( 0 );

###################################
###########  END  #################
###################################

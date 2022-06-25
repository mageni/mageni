###############################################################################
# OpenVAS Vulnerability Test
# $Id: netbios_name_get.nasl 11403 2018-09-15 09:16:15Z cfischer $
#
# Using NetBIOS to retrieve information from a SMB host
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 1999 SecuriTeam
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10150");
  script_version("$Revision: 11403 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:16:15 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Using NetBIOS to retrieve information from a SMB host");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 1999 SecuriTeam");
  script_family("Service detection");
  script_dependencies("cifs445.nasl");

  script_tag(name:"summary", value:"This script is using NetBIOS (port UDP:137) to retrieve information
  from a SMB host.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

SCRIPT_DESC = "Using NetBIOS to retrieve information from a SMB host";
BANNER_TYPE = "NetBIOS information";

function isprint( c ) {

  min = ord( "!" );
  max = ord( "~" );
  ordc = ord( c );
  if( ordc > max ) return FALSE;
  if( ordc < min ) return FALSE;
  return TRUE;
}

# do not test this bug locally

NETBIOS_LEN = 50;

sendata = raw_string(
rand()%255, rand()%255, 0x00, 0x00, 0x00,
0x01, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x20, 0x43, 0x4B,
0x41, 0x41, 0x41, 0x41, 0x41,
0x41, 0x41, 0x41, 0x41, 0x41,
0x41, 0x41, 0x41, 0x41, 0x41,
0x41, 0x41, 0x41, 0x41, 0x41,
0x41, 0x41, 0x41, 0x41, 0x41,
0x41, 0x41, 0x41, 0x41, 0x41,
0x00, 0x00, 0x21, 0x00, 0x01 );

#query *SMBSERVER<20> - by KK Liu 03/24/2004
sendata_SMBSERVER = raw_string(
rand()%255, rand()%255, 0x00, 0x10, 0x00,
0x01, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x20, 0x43, 0x4b,
0x46, 0x44, 0x45, 0x4e, 0x45,
0x43, 0x46, 0x44, 0x45, 0x46,
0x46, 0x43, 0x46, 0x47, 0x45,
0x46, 0x46, 0x43, 0x43, 0x41,
0x43, 0x41, 0x43, 0x41, 0x43,
0x41, 0x43, 0x41, 0x43, 0x41,
0x00, 0x00, 0x21, 0x00, 0x01 );

hostname_found = FALSE;
group_found = FALSE;
messenger_found = FALSE;
candidate = "";
hostdetails_name = "";
hostip = get_host_ip();

dsport = 137;

if( ! get_udp_port_state( dsport ) ) {
  set_kb_item( name:"SMB/name", value:hostip );
  exit( 0 );
}

soc = open_sock_udp( dsport );
if( ! soc ) exit( 0 );

send( socket:soc, data:sendata, length:NETBIOS_LEN );
result = recv( socket:soc, length:4096 );

#query *SMBSERVER<20> - by KK Liu 03/24/2004
if( strlen( result ) < 56) {
  send( socket:soc, data:sendata_SMBSERVER, length:NETBIOS_LEN );
  result = recv( socket:soc, length:4096 );
}

close( soc );

if( strlen( result ) > 56 ) {

  register_service( port:dsport, proto:"netbios-ns", ipproto:"udp" );

  hole_answer = "";
  hole_data = result;
  location = 0;
  location = location + 56;
  name_list = make_list();

  num_of_names = ord( hole_data[location] );
  if( num_of_names > 0 ) {
    hole_answer = string( hole_answer, "The following ", num_of_names, " NetBIOS names have been gathered :\n");
  }

  location++;

  for( name_count = 0; name_count < num_of_names; name_count++ ) {
    name = "";
    for( name_copy = 0; name_copy < 15; name_copy++ ) {
      loc = location + name_copy + name_count * 18;
      if( isprint( c:hole_data[location + name_copy + name_count * 18] ) ) {
        name = string( name, hole_data[ location + name_copy + name_count * 18] );
      } else {
        name = string( name, " " );
      }
    }

    loc = location + 16 + name_count * 18;

    # Win2k/WinXP sends 0xc4-196 and 0x44-68 as the loc name flags
    if( hole_data[loc] == raw_string( 68 ) ) {

      subloc = location + 15 + name_count * 18;

      if( ord( hole_data[subloc] ) == 32 ) {

        if( ! hostname_found && name ) {
          tmp_name = chomp( name );
          set_kb_item( name:"SMB/name", value:tmp_name );
          hostname_found = TRUE;
          hostdetails_name = tmp_name;
        }

        name_list = make_list( name_list, name + " = This is the computer name." );

      } else if( ord( hole_data[subloc] ) == 0 ) {

        candidate = name;

        if( ! ( "~" >< name ) ) {
          if( ! hostname_found && name ) {
            tmp_name = chomp( name );
            set_kb_item( name:"SMB/name", value:tmp_name );
            hostname_found = TRUE;
            hostdetails_name = tmp_name;
          }
        }
      }

      # nb: Set the current logged in user based on the last entry
      if( hole_data[subloc] == raw_string( 3 ) ) {
        # Ugh, we can get multiple usernames with TS or Citrix
        # Also, the entry is the same for the local workstation or user name
        username = name;
        name_list = make_list( name_list, name + " = This is the current logged in user or registered workstation name." );
      }

      if( ord( hole_data[subloc] ) == 27 ) {
        if( ! group_found && name ) {
          set_kb_item( name:"SMB/workgroup", value:chomp( name ) );
          group_found = TRUE;
        }
      }

      if( hole_data[subloc] == raw_string( 1 ) ) {
        name_list = make_list( name_list, name + " = Computer name that is registered for the messenger service on a computer that is a WINS client." );
        messenger_found = TRUE;
        messenger = name;
      }

      if( hole_data[subloc] == raw_string( 190 ) ) {
        name_list = make_list( name_list, name + " = A unique name that is registered when the Network Monitor agent is started on the computer." );
      }

      if( hole_data[subloc] == raw_string( 31 ) ) {
        name_list = make_list( name_list, name + " = A unique name that is registered for Network dynamic data exchange (DDE) when the NetDDE service is started on the computer." );
      }
    }

    # nb: Set the workgroup info on WinXP
    if( hole_data[loc] == raw_string( 196 ) ) {

      subloc = location + 15 + name_count * 18;

      if( hole_data[subloc] == raw_string( 0 ) ) {
        if( ! group_found && name ) {
          set_kb_item( name:"SMB/workgroup", value:chomp( name ) );
          group_found = TRUE;
        }
        name_list = make_list( name_list, name + " = Workgroup / Domain name" );
      }

      if( hole_data[subloc] == raw_string( 30 ) ) {
        name_list = make_list( name_list, name + " = Workgroup / Domain name (part of the Browser elections)" );
      }

      if( hole_data[subloc] == raw_string( 27 ) ) {
        name_list = make_list( name_list, name + " = Workgroup / Domain name (elected Master Browser)" );
      }

      if( hole_data[subloc] == raw_string( 28 ) ) {
        name_list = make_list( name_list, name + " = Workgroup / Domain name (Domain Controller)" );
      }

      if( hole_data[subloc] == raw_string( 191 ) ) {
        name_list = make_list( name_list, name + " = A group name that is registered when the Network Monitor agent is started on the computer." );
      }
    }

    # WinNT sends 0x04-4 and 0x84-132 as the loc name flags
    if( hole_data[loc] == raw_string( 4 ) ) {

      subloc = location + 15 + name_count * 18;

      if( hole_data[subloc] == raw_string( 0 ) ) {

        if( ! hostname_found && name ) {
          tmp_name = chomp( name );
          set_kb_item( name:"SMB/name", value:tmp_name );
          hostname_found = TRUE;
          hostdetails_name = tmp_name;
        }

        if( "~" >!< name ) {
          name_list = make_list( name_list, name + " = This is the computer name registered for workstation services by a WINS client." );
        } else {
          name_list = make_list( name_list, name );
        }
      }

      # nb: Set the current logged in user based on the last entry
      if( hole_data[subloc] == raw_string( 3 ) ) {
        # Ugh, we can get multiple usernames with TS or Citrix
        username = name;
        name_list = make_list( name_list, name + " = This is the current logged in user registered for this workstation." );
      }

      if( hole_data[subloc] == raw_string( 1 ) ) {
        name_list = make_list( name_list, name + " = Computer name that is registered for the messenger service on a computer that is a WINS client." );
        messenger_found = TRUE;
        messenger = name;
      }

      if( hole_data[subloc] == raw_string( 190 ) ) {
        name_list = make_list( name_list, name + " = A unique name that is registered when the Network Monitor agent is started on the computer." );
      }

      if( hole_data[subloc] == raw_string( 31 ) ) {
        name_list = make_list( name_list, name + " = A unique name that is registered for Network dynamic data exchange (DDE) when the NetDDE service is started on the computer." );
      }

      if( hole_data[subloc] == raw_string( 32 ) ) {
        name_list = make_list( name_list, name + " = Computer name" );
      }
    }

    loc = location + 16 + name_count * 18;

    # nb: Set the workgroup info on WinNT
    if( hole_data[loc] == raw_string( 132 ) ) {

      subloc = location + 15 + name_count * 18;

      if( hole_data[subloc] == raw_string( 0 ) ) {
        if( ! group_found && name ) {
          set_kb_item( name:"SMB/workgroup", value:chomp( name ) );
          group_found = TRUE;
        }
        name_list = make_list( name_list, name + " = Workgroup / Domain name" );
      }

      if( hole_data[subloc] == raw_string( 30 ) ) {
        name_list = make_list( name_list, name + " = Workgroup / Domain name (part of the Browser elections)" );
      }

      if( hole_data[subloc] == raw_string( 27 ) ) {
        name_list = make_list( name_list, name + " = Workgroup / Domain name (elected Master Browser)" );
      }

      if( hole_data[subloc] == raw_string( 28 ) ) {
        name_list = make_list( name_list, name + " = Workgroup / Domain name (Domain Controller)" );
      }

      if( hole_data[subloc] == raw_string( 191 ) ) {
        name_list = make_list( name_list, name + " = A group name that is registered when the Network Monitor agent is started on the computer." );
      }
    }
  }

  # Sort to not report changes on delta reports if just the order is different
  name_list = sort( name_list );
  foreach name( name_list ) {
    hole_answer += " " + name + '\n';
  }

  location += num_of_names * 18;
  adapter_name = "";

  for( adapter_count = 0; adapter_count < 6; adapter_count++ ) {
    loc = location + adapter_count;
    if( adapter_count == 5 )
      col = "";
    else
      col = ":";
    adapter_name += tolower( string( hex( ord( hole_data[loc] ) ), col ) ) - "0x";
  }

  if( adapter_name == "00:00:00:00:00:00" ) {
    set_kb_item( name:"SMB/samba", value:TRUE );
    hole_answer += string( "\nThis SMB server seems to be a SAMBA server (this is not a security risk, this is for your information). This can be told because this server claims to have a null MAC address." );
    register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:dsport, proto:"udp", banner:"null MAC address of a Samba server", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    hole_answer += string( "\nThe remote host has the following MAC address on its adapter :\n" );
    hole_answer += " " + adapter_name;
    register_host_detail( name:"MAC", value:adapter_name, desc:SCRIPT_DESC );
    register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:dsport, proto:"udp", desc:SCRIPT_DESC, runs_key:"windows" );
  }
  hole_answer += string( "\n\nIf you do not want to allow everyone to find the NetBIOS name of your computer, you should filter incoming traffic to this port." );
  log_message( port:dsport, data:hole_answer, protocol:"udp" );
}

if( ! hostname_found ) {
  if( candidate ) {
    tmp_candidate = chomp( candidate );
    set_kb_item( name:"SMB/name", value:tmp_candidate );
    hostname_found = TRUE;
    hostdetails_name = tmp_candidate;
  } else {
    set_kb_item( name:"SMB/name", value:hostip );
  }
}

if( hostname_found && ! isnull( hostdetails_name ) && hostdetails_name != '' && hostdetails_name != hostip ) {
  register_host_detail( name:"SMB-HOST-NAME", value:hostdetails_name, desc:SCRIPT_DESC );
}

if( username ) {
  set_kb_item( name:"SMB/username", value:username );
}

if( messenger_found && messenger) {
  set_kb_item( name:"SMB/username", value:messenger );
}

exit( 0 );

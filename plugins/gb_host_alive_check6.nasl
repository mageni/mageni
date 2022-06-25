###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_host_alive_check6.nasl 13775 2019-02-20 07:45:12Z cfischer $
#
# Mark host as dead if going offline (failed ICMP ping) during scan - Phase 6
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.108220");
  script_version("$Revision: 13775 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-20 08:45:12 +0100 (Wed, 20 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-08-17 11:18:02 +0200 (Thu, 17 Aug 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Mark host as dead if going offline (failed ICMP ping) during scan - Phase 6");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("default_http_auth_credentials.nasl", "default_ssh_credentials.nasl", "find_service_nmap.nasl", "toolcheck.nasl",
                      "gb_host_alive_check5.nasl", "unknown_services.nasl"); # Trying to enforce that this NVT is running late in its category
  script_mandatory_keys("global_settings/mark_host_dead_failed_icmp", "Tools/Present/ping");

  script_tag(name:"summary", value:"This plugin checks the target host in the phase 6 of a scan
  and marks it as 'dead' to the scanner if it is not answering to an ICMP ping anymore.

  NOTE: This plugin/behavior is disabled by default and needs to be enabled within the
  'Global variable settings' (OID: 1.3.6.1.4.1.25623.1.0.12288) of the scan config in use.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");

if( ! cmd = get_kb_item( "Tools/Present/ping/bin" ) )
  exit( 0 );

i = 0;
ping_args = make_list();
ping_args[i++] = cmd;

if( extra_cmd = get_kb_item( "Tools/Present/ping/extra_cmd" ) )
  ping_args[i++] = extra_cmd;

ping_args[i++] = "-c 3";
ping_args[i++] = get_host_ip();

ping = pread( cmd:cmd, argv:ping_args, cd:TRUE );
if( "3 packets transmitted, 0 received" >< ping || "3 packets transmitted, 0 packets received" >< ping ) { #nb: inetutils vs. iputils
  log_message( port:0, data:"Target host seems to be suspended or disconnected from the Network. It was marked as 'dead' to the scanner and the scan was aborted." );
  register_host_detail( name:"dead", value:1 );
  set_kb_item( name:"Host/dead", value:TRUE );
}

exit( 0 );
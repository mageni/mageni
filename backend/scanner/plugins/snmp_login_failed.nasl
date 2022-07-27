###############################################################################
# OpenVAS Vulnerability Test
# $Id: snmp_login_failed.nasl 13257 2019-01-24 08:14:40Z cfischer $
#
# SNMP Login Failed For Authenticated Checks
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108541");
  script_version("$Revision: 13257 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-24 09:14:40 +0100 (Thu, 24 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-24 09:05:25 +0100 (Thu, 24 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SNMP Login Failed For Authenticated Checks");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SNMP");
  script_dependencies("snmp_detect.nasl");
  script_mandatory_keys("login/SNMP/failed");

  script_tag(name:"summary", value:"It was NOT possible to login using the provided SNMPv1 /
  SNMPv2 community string / SNMPv3 credentials. Hence version checks based on SNMP might not work
  (if no other default community string was found).");

  script_tag(name:"solution", value:"Recheck the SNMPv1/SNMPv2 community string or SNMPv3 credentials
  as well as the output of the VT 'A SNMP Agent is running' (OID: 1.3.6.1.4.1.25623.1.0.10265).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

port = get_kb_item( "login/SNMP/failed/port" );
if( ! port )
  port = 0;

log_message( port:port, proto:"udp" );
exit( 0 );
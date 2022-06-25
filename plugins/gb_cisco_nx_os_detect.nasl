###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_nx_os_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cisco NX-OS Detection (SNMP)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103799");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-10-09 16:24:09 +0200 (Wed, 09 Oct 2013)");
  script_name("Cisco NX-OS Detection (SNMP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  script_tag(name:"summary", value:"This script performs SNMP based detection of Cisco NX-OS.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("dump.inc");
include("snmp_func.inc");

function parse_result(data) {

  if(strlen(data) < 8) return FALSE;

  for(v=0; v < strlen(data); v++) {
      if(ord(data[v]) == 43 && ord(data[v-1]) == 13) {
        ok = TRUE;
        break;
      }
      oid_len = ord(data[v]);
  }

  if(!ok || oid_len < 8)return FALSE;

  tmp = substr(data,(v+oid_len+2));

  if (tmp && !isprint (c:tmp[0])) {
    tmp = substr(tmp,1,strlen(tmp)-1);
  }

  return tmp;

}

function map_model( mod )
{
  if( mod == "n1000v" ) return "1000V";
  if( mod == "n9000" )  return "N9K";
  if( mod == "n8000" )  return "8000";
  if( mod == "n7000" )  return "7000";
  if( mod == "n6000" )  return "6000";
  if( mod == "n5000" )  return "5000";
  if( mod == "n4000" )  return "4000";
  if( mod == "n3500")   return "3500";
  if( mod == "n3000" )  return "3000";
  if( mod == "n2000" )  return "2000";
}

port    = get_snmp_port(default:161);
sysdesc = get_snmp_sysdesc(port:port);
if(!sysdesc) exit(0);

# Example:
# Cisco NX-OS(tm) n7000, Software (n7000-s1-dk9), Version 5.2(3a), RELEASE SOFTWARE Copyright (c) 2002-2011 by Cisco Systems, Inc. Compiled 12/15/2011 12:00:00;
# Cisco NX-OS(tm) ucs, Software (ucs-6100-k9-system), Version 5.0(3)N2(2.04b), RELEASE SOFTWARE Copyright (c) 2002-2012 by Cisco Systems, Inc. Compiled 10/21/2012 11:00:00
if("Cisco NX-OS" >!< sysdesc)exit(0);

set_kb_item( name:"cisco/nx_os/detected", value:TRUE );

nx_version = eregmatch(pattern:"Version ([^,]+),", string:sysdesc);
if(isnull(nx_version[1]))exit(0);

nx_ver = nx_version[1];

set_kb_item(name:"cisco/nx_os/snmp/version", value: nx_ver);

model = "unknown";
device = "unknown";
source = "snmp";

community = snmp_get_community( port:port );
if(!community)community = "public";

SNMP_BASE = 40;
COMMUNITY_SIZE = strlen(community);
sz = COMMUNITY_SIZE % 256;

len = SNMP_BASE + COMMUNITY_SIZE;

for (i=0; i<3; i++) {

  soc = open_sock_udp(port);
  if(!soc)continue;

  # snmpget -v<version> -c <community> <host> 1.3.6.1.2.1.47.1.1.1.1.2.149
  sendata = raw_string(0x30,len,0x02,0x01,i,0x04,sz) +
            community +
            raw_string(0xa0,0x21,0x02,0x04,0x7f,0x45,0x71,0x96,
                       0x02,0x01,0x00,0x02,0x01,0x00,0x30,0x13,
                       0x30,0x11,0x06,0x0d,0x2b,0x06,0x01,0x02,
                       0x01,0x2f,0x01,0x01,0x01,0x01,0x02,0x81,
                       0x15,0x05,0x00);

  send(socket:soc, data:sendata);
  result = recv(socket:soc, length:400, timeout:1);
  close(soc);

  if(!result || ord(result[0]) != 48)continue;

  # Nexus7000 C7010 (10 Slot) Chassis
  # UCS 6100 Series Fabric Interconnect;
  if(!res = parse_result(data:result))continue;

  if( "Nexus" >< res || res =~ "^N9K" )
  {
    device = "Nexus";

    if( res =~ "^N9K-" )
      model = res;
    else
    {
      m = eregmatch( pattern:"Nexus\s*([^\r\n\s]+)[^\r\n]*\s+Chassis", string:res );
      if( ! isnull( m[1] ) ) model = m[1];
    }
    break;
  }
  else if( "MDS" >< res )
  {
    device = "MDS";
    m = eregmatch( pattern:"MDS\s*([^\r\n\s]+)[^\r\n]*\s+Chassis", string:res );
    if( ! isnull( m[1] ) ) model = m[1];
    break;
  }
}

if( device == "unknown" )
{
  if( "titanium" >< sysdesc )
  {
    device = 'MDS';
  }
  else if( sysdesc =~ "Cisco NX-OS\(tm\) (n[0-9]+[^,]+)" )
  {
    device = "Nexus";
    tmp_model = eregmatch( pattern:"Cisco NX-OS\(tm\) (n[0-9]+[^,]+)", string: sysdesc );
    if( ! isnull( tmp_model[1] ) ) model = map_model( mod:tmp_model[1] );
  }
}

set_kb_item(name:"cisco/nx_os/" + source + "/device", value:device);
set_kb_item(name:"cisco/nx_os/" + source + "/model", value:model);
exit(0);


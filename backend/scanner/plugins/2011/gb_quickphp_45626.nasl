###############################################################################
# OpenVAS Vulnerability Test
#
# QuickPHP 'index.php' Remote Source Code Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103002");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2011-01-03 14:40:34 +0100 (Mon, 03 Jan 2011)");
  script_bugtraq_id(45626);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("QuickPHP 'index.php' Remote Source Code Disclosure Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 5723);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/45626");
  script_xref(name:"URL", value:"http://www.zachsaw.co.cc/?pg=quickphp_php_tester_debugger");

  script_tag(name:"summary", value:"QuickPHP is prone to a remote source-code-disclosure vulnerability
  because it fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to view the source code
  of files in the context of the server process. This may aid in further attacks.");

  script_tag(name:"affected", value:"QuickPHP 1.10.0 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:5723);
host = http_host_name(dont_add_port:TRUE);

if(!can_host_php(port:port))exit(0);

phps = http_get_kb_file_extensions( port:port, host:host, ext:"php" );
if(!isnull(phps)) {
  phps = make_list(phps);
} else {
  phps = make_list("/index.php");
}

max   = 5;
count = 1;

foreach php (phps) {

  count++;

  url = string(php,".");

  if(http_vuln_check(port:port, url:url, pattern:"(<\?([ ]+)|<\?php)")) {
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
  if(count >= max) exit(0);
}

exit(0);

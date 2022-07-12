# OpenVAS Vulnerability Test
# Description: Quicktime/Darwin Remote Admin Exploit
#
# Authors:
# Michael Scheidell SECNAP Network Security
#
# Copyright:
# Copyright (C) 2003 Michael Scheidell
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
  script_oid("1.3.6.1.4.1.25623.1.0.11278");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(6954, 6955, 6956, 6957, 6958, 6960, 6990);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2003-0050", "CVE-2003-0051", "CVE-2003-0052", "CVE-2003-0053", "CVE-2003-0054", "CVE-2003-0055");
  script_name("Quicktime/Darwin Remote Admin Exploit");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Michael Scheidell");
  script_family("Gain a shell remotely");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 1220);
  script_mandatory_keys("QuickTime_Darwin/banner");

  script_xref(name:"URL", value:"http://www.atstake.com/research/advisories/2003/a022403-1.txt");

  script_tag(name:"solution", value:"Obtain a patch or new software from Apple or block this port (TCP 1220) from internet access.");

  script_tag(name:"summary", value:"Cross site scripting, buffer overflow and remote command
  execution on QuickTime/Darwin Streaming Administration Server.");

  script_tag(name:"insight", value:"This is due to parsing problems with per script:

  parse_xml.cgi.

  The worst of these vulnerabilities allows for remote command execution usually as root
  or administrator.

  These servers are installed by default on port 1220.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:1220);
banner = get_http_banner(port:port);
if(!banner || ("QuickTime" >!< banner && "DSS/" >!< banner))
  exit(0);

foreach dir (make_list_unique("/AdminHTML", cgi_dirs(port:port))) {

  if(dir == "/")
    dir = "";

  url = dir + "/parse_xml.cgi";

  if(is_cgi_installed_ka(item:url, port:port)) {
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
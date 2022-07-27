# OpenVAS Vulnerability Test
# $Id: apache_bat_exec.nasl 6540 2017-07-05 12:42:02Z cfischer $
# Description: Apache Remote Command Execution via .bat files
#
# Authors:
# Matt Moore <matt@westpoint.ltd.uk>
#
# Copyright:
# Copyright (C) 2002 Matt Moore
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
  script_oid("1.3.6.1.4.1.25623.1.0.10938");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(4335);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2002-0061");
  script_name("Apache Remote Command Execution via .bat files");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2002 Matt Moore");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("apache/banner");

  script_tag(name:"solution", value:"This bug is fixed in 1.3.24 and 2.0.34-beta, or remove /cgi-bin/test-cgi.bat.");

  script_tag(name:"summary", value:"The Apache 2.0.x Win32 installation is shipped with a
  default script, /cgi-bin/test-cgi.bat, that allows an attacker to execute
  commands on the Apache server (although it is reported that any .bat file
  could open this vulnerability.)");

  script_tag(name:"impact", value:"An attacker can send a pipe character with commands appended as parameters,
  which are then executed by Apache.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

# nb: The check makes request for cgi-bin/test-cgi.bat?|echo - which should return
# an HTTP 500 error containing the string 'ECHO is on'
# We just check for 'ECHO' (capitalized), as this should remain the same across
# most international versions of Windows(?)

include("http_func.inc");

port = get_http_port(default:80);
sig = get_http_banner(port:port);
if( !sig || "Apache" >!< sig )
  exit(0);

url = "/cgi-bin/test-cgi.bat?|echo";
req = http_get(item:url, port:port);
res = http_send_recv(port:port, data:req);

if("ECHO" >< res) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
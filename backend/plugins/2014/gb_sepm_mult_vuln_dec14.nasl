###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sepm_mult_vuln_dec14.nasl 11974 2018-10-19 06:22:46Z cfischer $
#
# Symantec Endpoint Protection Manager Multiple Vulnerabilities - Dec14
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805203");
  script_version("$Revision: 11974 $");
  script_cve_id("CVE-2014-3439", "CVE-2014-3438", "CVE-2014-3437");
  script_bugtraq_id(70843, 70844, 70845);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:22:46 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-12-04 09:43:28 +0530 (Thu, 04 Dec 2014)");
  script_name("Symantec Endpoint Protection Manager Multiple Vulnerabilities - Dec14");

  script_tag(name:"summary", value:"This host is installed with Symantec
  Endpoint Protection Manager and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - The /console/Highlander_docs/SSO-Error.jsp script does not validate
    input to the 'ErrorMsg' parameter before returning it to users.

  - ConsoleServlet does not properly sanitize user input supplied via the
    'ActionType' parameter.

  - Incorrectly configured XML parser accepting XML external entities from an
    untrusted source.

  - The /portal/Loading.jsp script does not validate input to the 'uri' parameter
    before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to gain access to arbitrary files, write to or overwrite arbitrary files and
  execute arbitrary script code in a user's browser session within the trust
  relationship between their browser and the server.");

  script_tag(name:"affected", value:"Symantec Endpoint Protection Manager (SEPM)
  12.1 before RU5.");

  script_tag(name:"solution", value:"Upgrade to Symantec Endpoint Protection Manager
  12.1 RU5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1031176");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8443);
  script_xref(name:"URL", value:"http://www.symantec.com");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");


http_port = get_http_port(default:8443);

##Send https request and Receive Response
res = http_get_cache(item:"/", port:http_port);

if(res && ">Symantec Endpoint Protection Manager<" >< res
       && res =~ "&copy.*Symantec Coorporation<")
{

  url = "/console/Highlander_docs/SSO-Error.jsp?ErrorMsg=<script>alert(document"
        + ".cookie)</script>";

  req = http_get(item:url, port:http_port);
  res = http_keepalive_send_recv(port:http_port, data:req);

  if(res =~ "HTTP/1\.. 200" && "<script>alert(document.cookie)</script>" >< res
         && ">SSO Error<" >< res)
  {
    security_message(port:http_port);
    exit(0);
  }
}

exit(99);

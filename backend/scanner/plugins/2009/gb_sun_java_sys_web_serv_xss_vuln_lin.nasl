###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_java_sys_web_serv_xss_vuln_lin.nasl 12746 2018-12-10 15:26:37Z cfischer $
#
# Sun Java System Web Server XSS Vulnerability (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:sun:java_system_web_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800812");
  script_version("$Revision: 12746 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-10 16:26:37 +0100 (Mon, 10 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-06-19 09:45:44 +0200 (Fri, 19 Jun 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-1934");
  script_bugtraq_id(35204);
  script_name("Sun Java System Web Proxy Server Vulnerabilities (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sun_one_java_sys_web_serv_detect_lin.nasl");
  script_mandatory_keys("Sun/JavaSysWebServ/Lin/Ver");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35338");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-21-116648-23-1");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-259588-1");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code,
  gain sensitive information by conducting XSS attacks in the context of a affected site.");

  script_tag(name:"affected", value:"Sun Java System Web Server versions 6.1 and before 6.1 SP11 on Linux.");

  script_tag(name:"insight", value:"The Flaw is due to error in 'Reverse Proxy Plug-in' which is not properly
  sanitized the input data before being returned to the user. This can be exploited to inject arbitrary web
  script or HTML via the query string in situations that result in a 502 Gateway error.");

  script_tag(name:"solution", value:"Update to Web Server version 6.1 SP11 or later.");

  script_tag(name:"summary", value:"This host has Sun Java Web Server running on Linux, which is prone
  to Cross-Site Scripting vulnerability.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos['version'];
path = infos['location'];

if( version_in_range( version:vers, test_version:"6.1", test_version2:"6.1.SP10" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"6.1.SP11", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
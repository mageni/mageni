###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nginx_mult_vuln.nasl 12890 2018-12-28 09:11:32Z asteins $
#
# nginx 1.9.5 < 1.14.1, 1.15.x < 1.15.6 Multiple Vulnerabilities
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.112419");
  script_version("$Revision: 12890 $");
  script_cve_id("CVE-2018-16843", "CVE-2018-16844");
  script_bugtraq_id(105868);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-12-28 10:11:32 +0100 (Fri, 28 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-11-12 11:41:11 +0100 (Mon, 12 Nov 2018)");

  script_name("nginx 1.9.5 < 1.14.1, 1.15.x < 1.15.6 Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Two security issues were identified in nginx HTTP/2 implementation,
  which might cause excessive memory consumption and CPU usage.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The issues affect nginx compiled with the ngx_http_v2_module (not
  compiled by default) if the 'http2' option of the 'listen' directive is
  used in a configuration file.");

  script_tag(name:"affected", value:"nginx versions 1.9.5 up to 1.14.0 and 1.15.x up to 1.15.5.");

  script_tag(name:"solution", value:"Upgrade nginx to version 1.14.1 or 1.15.6 respectively.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"http://mailman.nginx.org/pipermail/nginx-announce/2018/000220.html");

  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("nginx_detect.nasl");
  script_mandatory_keys("nginx/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

CPE = "cpe:/a:nginx:nginx";

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!vers = get_app_version(cpe:CPE, port:port)) exit(0);

if(version_in_range(version:vers, test_version:"1.9.5", test_version2:"1.14.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.14.1");
  security_message(port:port, data:report);
  exit(0);
}

if(version_in_range(version:vers, test_version:"1.15.0", test_version2:"1.15.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.15.5");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

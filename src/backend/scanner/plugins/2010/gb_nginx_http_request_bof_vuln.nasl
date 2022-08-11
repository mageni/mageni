###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nginx_http_request_bof_vuln.nasl 13859 2019-02-26 05:27:33Z ckuersteiner $
#
# nginx HTTP Request Remote Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

CPE = "cpe:/a:nginx:nginx";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801636");
  script_version("$Revision: 13859 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-26 06:27:33 +0100 (Tue, 26 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-11-18 06:30:08 +0100 (Thu, 18 Nov 2010)");
  script_cve_id("CVE-2009-2629");
  script_bugtraq_id(36384);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("nginx HTTP Request Remote Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/180065");
  script_xref(name:"URL", value:"http://sysoev.ru/nginx/patch.180065.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("nginx_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("nginx/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code
  within the context of the affected application. Failed exploit attempts will result in a denial-of-service
  condition.");

  script_tag(name:"affected", value:"nginx versions 0.1.0 through 0.5.37, 0.6.x before 0.6.39, 0.7.x before
  0.7.62 and 0.8.x before 0.8.15.");

  script_tag(name:"insight", value:"The flaw is due to an error in 'src/http/ngx_http_parse.c' which
  allows remote attackers to execute arbitrary code via crafted HTTP requests.");

  script_tag(name:"solution", value:"Upgrade to nginx versions 0.5.38, 0.6.39, 0.7.62 or 0.8.15");

  script_tag(name:"summary", value:"This host is running nginx and is prone to buffer-overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if(version_in_range(version: version, test_version:"0.1.0", test_version2:"0.5.37") ||
   version_in_range(version: version, test_version:"0.6.0", test_version2:"0.6.38") ||
   version_in_range(version: version, test_version:"0.7.0", test_version2:"0.7.61")) {
  report = report_fixed_ver( installed_version:version, fixed_version:"0.5.37/0.6.38/0.7.61" );
  security_message(port:port, data:report);
  exit(0);
}

exit( 99 );

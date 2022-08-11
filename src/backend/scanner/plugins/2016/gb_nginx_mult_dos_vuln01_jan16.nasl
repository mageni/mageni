###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nginx_mult_dos_vuln01_jan16.nasl 13859 2019-02-26 05:27:33Z ckuersteiner $
#
# Nginx Server Multiple Denial Of Service Vulnerabilities 01 - Jan16
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806849");
  script_version("$Revision: 13859 $");
  script_cve_id("CVE-2016-0742", "CVE-2016-0746", "CVE-2016-0747");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-26 06:27:33 +0100 (Tue, 26 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-01-27 17:26:59 +0530 (Wed, 27 Jan 2016)");

  script_name("Nginx Server Multiple Denial Of Service Vulnerabilities 01 - Jan16");

  script_tag(name:"summary", value:"This host is installed with nginx server
  and is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws as,

  - An invalid pointer dereference might occur during DNS server response processing.

  - The use-after-free condition might occur during CNAME response processing.

  - The CNAME resolution was insufficiently limited.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to trigger arbitrary name
  resolution to cause excessive resource consumption in worker processes, to forge UDP packets from the DNS
  server to cause worker process crash.");

  script_tag(name:"affected", value:"nginx versions from 0.6.18 to 1.9.9, note 1.8.1 is not vulnerable");

  script_tag(name:"solution", value:"Upgrade to nginx version 1.9.10 or 1.8.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://mailman.nginx.org/pipermail/nginx/2016-January/049700.html");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("nginx_detect.nasl");
  script_mandatory_keys("nginx/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!ngxPort = get_app_port(cpe:CPE))
  exit(0);

if(!ngxVer = get_app_version(cpe:CPE, port:ngxPort))
  exit(0);

## version history referred from https://en.wikipedia.org/wiki/Nginx
if(ngxVer =~ "^0\.") {
  if(version_in_range(version:ngxVer, test_version:"0.6", test_version2:"0.8.55")) {
    report = report_fixed_ver( installed_version:ngxVer, fixed_version:"1.9.10/1.8.1");
    security_message(port:ngxPort, data:report);
    exit(0);
  }
}

if(ngxVer =~ "^1\.") {
  if(version_is_less(version:ngxVer, test_version:"1.8.1")) {
    report = report_fixed_ver(installed_version:ngxVer, fixed_version:"1.9.10/1.8.1");
    security_message(port:ngxPort, data:report);
    exit(0);
  }
}

if(ngxVer =~ "^1\.9") {
  if(version_is_less(version:ngxVer, test_version:"1.9.10")) {
    report = report_fixed_ver( installed_version:ngxVer, fixed_version:"1.9.10");
    security_message(port:ngxPort, data:report);
    exit(0);
  }
}

exit(99);

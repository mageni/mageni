###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ntopng_mult_vuln.nasl 11982 2018-10-19 08:49:21Z mmartin $
#
# ntopng Multiple Vulnerabilities
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:ntop:ntopng";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112105");
  script_version("$Revision: 11982 $");
  script_cve_id("CVE-2017-7458", "CVE-2017-7459", "CVE-2017-7416");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 10:49:21 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-06 15:50:16 +0200 (Mon, 06 Nov 2017)");
  script_name("ntopng Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The host is installed with ntopng and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities exist within ntopng:

  - The NetworkInterface::getHost function in NetworkInterface.cpp allows remote attackers to cause a denial of service
      (NULL pointer dereference and application crash) via an empty field that should have contained a hostname or IP address (CVE-2017-7458).

  - HTTP Response Splitting (CVE-2017-7459).

  - Cross-site scripting (XSS) because GET and POST parameters are improperly validated (CVE-2017-7416).");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to cause a denial of service and/or inject arbitrary script code.");

  script_tag(name:"affected", value:"ntopng prior to version 3.0");

  script_tag(name:"solution", value:"Upgrade to ntopng 3.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://github.com/ntop/ntopng/blob/3.0/CHANGELOG.md");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_ntopng_detect.nasl");
  script_mandatory_keys("ntopng/installed");
  script_require_ports("Services/www", 3000);

  script_xref(name:"URL", value:"http://www.ntop.org/");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!appPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!ntopngVer = get_app_version(cpe:CPE, port:appPort)){
  exit(0);
}

if(version_is_less(version:ntopngVer, test_version:"3.0"))
{
    report = report_fixed_ver(installed_version:ntopngVer, fixed_version:"3.0");
    security_message(data:report, port:appPort);
    exit(0);
}

exit(99);

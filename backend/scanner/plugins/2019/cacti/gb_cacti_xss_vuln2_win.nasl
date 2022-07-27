###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cacti_xss_vuln2_win.nasl 13131 2019-01-18 03:06:38Z ckuersteiner $
#
# Cacti < 1.2.0 Multiple XSS Vulnerabilities (Windows)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = 'cpe:/a:cacti:cacti';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141890");
  script_version("$Revision: 13131 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-18 04:06:38 +0100 (Fri, 18 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-18 10:03:50 +0700 (Fri, 18 Jan 2019)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2018-20723", "CVE-2018-20724", "CVE-2018-20725", "CVE-2018-20726");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cacti < 1.2.0 Multiple XSS Vulnerabilities (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("cacti_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("cacti/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Cacti is prone to multiple cross-site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Cacti is prone to multiple cross-site scripting vulnerabilities:

  - Cross-site scripting (XSS) vulnerability in color_templates.php (CVE-2018-20723)

  - Cross-site scripting (XSS) vulnerability in pollers.php (CVE-2018-20724)

  - Cross-site scripting (XSS) vulnerability in graph_templates.php  (CVE-2018-2072)

  - Cross-site scripting (XSS) vulnerability in host.php (CVE-2018-20726)");

  script_tag(name:"affected", value:"Cacti prior to version 1.2.0.");

  script_tag(name:"solution", value:"Update to version 1.2.0 or later.");

  script_xref(name:"URL", value:"https://github.com/Cacti/cacti/issues/2215");
  script_xref(name:"URL", value:"https://github.com/Cacti/cacti/issues/2212");
  script_xref(name:"URL", value:"https://github.com/Cacti/cacti/issues/2214");
  script_xref(name:"URL", value:"https://github.com/Cacti/cacti/issues/2213");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.2.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

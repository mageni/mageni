###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyadmin_mult_xss_vuln01_july16_lin.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# phpMyAdmin SQL Injection and Multiple XSS Vulnerabilities July16 (Linux)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106490");
  script_version("$Revision: 11863 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-03 09:57:21 +0700 (Tue, 03 Jan 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2016-6615", "CVE-2016-6616");

  script_bugtraq_id(95041);

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpMyAdmin SQL Injection and Multiple XSS Vulnerabilities July16 (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"phpMyAdmin is prone to a SQL injection and multiple cross-site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks the banner.");

  script_tag(name:"insight", value:"Multiple XSS vulnerabilities were found in the following areas:

  - Navigation pane and database/table hiding feature. A specially-crafted database name can be used to trigger
an XSS attack.

  - The 'Tracking' feature. A specially-crafted query can be used to trigger an XSS attack.

  - GIS visualization feature.

An additional vulnerability was found in the 'User group' and 'Designer' features:

  - a user can execute an SQL injection attack against the account of the control user.");

  script_tag(name:"affected", value:"phpMyAdmin versions 4.4.x prior to 4.4.15.8 and 4.6.x prior to 4.6.4.");

  script_tag(name:"solution", value:"Update to version 4.4.15.8 or 4.6.4.");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-38/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^4\.4\.") {
  if (version_is_less(version: version, test_version: "4.4.15.8")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "4.4.15.8");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^4\.6\.") {
  if (version_is_less(version: version, test_version: "4.6.4")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "4.6.4");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);

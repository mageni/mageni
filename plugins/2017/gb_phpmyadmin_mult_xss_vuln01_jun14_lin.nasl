###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyadmin_mult_xss_vuln01_jun14_lin.nasl 11977 2018-10-19 07:28:56Z mmartin $
#
# phpMyAdmin Multiple XSS Vulnerabilities June14 (Linux)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.112009");
  script_version("$Revision: 11977 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 09:28:56 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-21 10:07:21 +0200 (Mon, 21 Aug 2017)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2014-4348");
  script_bugtraq_id(68201);

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpMyAdmin Multiple XSS Vulnerabilities June14 (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"phpMyAdmin is prone to multiple cross-site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks the banner.");

  script_tag(name:"insight", value:"Multiple XSS vulnerabilities allow remote authenticated users to inject arbitrary web script or HTML via a crafted
      (1) database name or (2) table name that is improperly handled after presence in (a) the favorite list or (b) recent tables.");

  script_tag(name:"affected", value:"phpMyAdmin versions 4.2.x prior to 4.2.4.");

  script_tag(name:"solution", value:"Update to version 4.2.4.");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2014-2/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^4\.2\.") {
  if (version_is_less(version: version, test_version: "4.2.4")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "4.2.4");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);

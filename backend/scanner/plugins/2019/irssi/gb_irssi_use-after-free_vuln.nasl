###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_irssi_use-after-free_vuln.nasl 13040 2019-01-11 14:10:45Z asteins $
#
# Irssi 1.1.x < 1.1.2 Use-After-Free Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112481");
  script_version("$Revision: 13040 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-11 15:10:45 +0100 (Fri, 11 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-11 15:04:12 +0100 (Fri, 11 Jan 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-5882");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Irssi 1.1.x < 1.1.2 Use-After-Free Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_irssi_detect_lin.nasl");
  script_mandatory_keys("irssi/detected");

  script_tag(name:"summary", value:"Irssi is prone to a use-after-free vulnerability.");
  script_tag(name:"insight", value:"The vulnerability occurs when hidden lines were expired
  from the scroll buffer.");
  script_tag(name:"impact", value:"Exploiting this vulnerability may affect the stability of Irssi.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"Irssi 1.1.x before 1.1.2.");
  script_tag(name:"solution", value:"Update to version 1.1.2.");

  script_xref(name:"URL", value:"https://irssi.org/security/irssi_sa_2019_01.txt");
  script_xref(name:"URL", value:"https://github.com/irssi/irssi/pull/948");
  script_xref(name:"URL", value:"https://irssi.org/NEWS/#v1-1-2");

  exit(0);
}

CPE = "cpe:/a:irssi:irssi";

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

vers = infos['version'];
path = infos['location'];

if(version_in_range(version: vers, test_version: "1.1.0", test_version2: "1.1.1")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "1.1.2", install_path: path);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

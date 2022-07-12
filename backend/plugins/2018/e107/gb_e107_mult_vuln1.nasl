##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_e107_mult_vuln1.nasl 12236 2018-11-07 05:34:17Z ckuersteiner $
#
# e107 < 2.1.9 Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:e107:e107";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141480");
  script_version("$Revision: 12236 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-07 06:34:17 +0100 (Wed, 07 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-09-14 16:39:34 +0700 (Fri, 14 Sep 2018)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2018-16388", "CVE-2018-16389");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("e107 < 2.1.9 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("e107_detect.nasl");
  script_mandatory_keys("e107/installed");

  script_tag(name:"summary", value:"e107 is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"e107 is prone to multiple vulnerabilities:

  - Arbitrary PHP code execution (CVE-2018-16388)

  - SQL Injection (CVE-2018-16389)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"e107 prior to version 2.1.9");

  script_tag(name:"solution", value:"Update to version 2.1.9 or later.");

  script_xref(name:"URL", value:"https://github.com/e107inc/e107/issues/3352");
  script_xref(name:"URL", value:"https://gist.github.com/ommadawn46/5cb22e7c66cc32a5c7734a8064b4d3f5");
  script_xref(name:"URL", value:"https://gist.github.com/ommadawn46/51e08e13e6980dcbcffb4322c29b93d0");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2.1.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.1.9");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_atlassian_bamboo_mult_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Atlassian Bamboo Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:atlassian:bamboo";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140603");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-12-14 12:10:23 +0700 (Thu, 14 Dec 2017)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2017-14589", "CVE-2017-14590");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Atlassian Bamboo Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_atlassian_bamboo_detect.nasl");
  script_mandatory_keys("AtlassianBamboo/Installed");

  script_tag(name:"summary", value:"Atlassian Bamboo is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Atlassian Bamboo is prone to multiple vulnerabilities:

  - Remote code execution through OGNL double evaluation (CVE-2017-14589)

  - Argument injection through Mercurial repository handling (CVE-2017-14590)");

  script_tag(name:"affected", value:"Atlassiona Bamboo versions prior to 6.1.6 and 6.2.x.");

  script_tag(name:"solution", value:"Update to 6.1.6, 6.2.5 or later.");

  script_xref(name:"URL", value:"https://confluence.atlassian.com/bamboo/bamboo-security-advisory-2017-12-13-939939816.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "6.1.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.6");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "6.2.0", test_version2: "6.2.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.5");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

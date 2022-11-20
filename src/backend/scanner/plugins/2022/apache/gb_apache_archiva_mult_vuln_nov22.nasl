# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

CPE = 'cpe:/a:apache:archiva';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126211");
  script_version("2022-11-16T13:33:39+0000");
  script_tag(name:"last_modification", value:"2022-11-16 13:33:39 +0000 (Wed, 16 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-11-16 11:01:36 +0000 (Wed, 16 Nov 2022)");
  script_tag(name:"cvss_base", value:"4.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:N/I:P/A:P");

  script_cve_id("CVE-2022-40308", "CVE-2022-40309");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Archiva < 2.2.9 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_archiva_detect.nasl");
  script_mandatory_keys("apache_archiva/installed");

  script_tag(name:"summary", value:"Apache Archiva is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The following vulnerabilities exist:

  - CVE-2022-40308: Users with write permissions to a repository can delete arbitrary directories.

  - CVE-2022-40309: It's possible to read the database file directly without logging in, when
  anonymous read is enabled");

  script_tag(name:"affected", value:"Apache Archiva prior to version 2.2.9.");

  script_tag(name:"solution", value:"Upgrade to version 2.2.9 or later.");

  script_xref(name:"URL", value:"https://archiva.apache.org/docs/2.2.9/release-notes.html");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/x01pnn0jjsw512cscxsbxzrjmz64n4cc");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/1odl4p85r96n27k577jk6ftrp19xfc27");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2.2.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.9");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

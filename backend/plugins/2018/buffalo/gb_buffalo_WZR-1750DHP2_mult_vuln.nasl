###############################################################################
# OpenVAS Vulnerability Test
#
# Buffalo WZR-1750DHP2 < 2.31 Multiple Vulnerabilities
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

CPE = 'cpe:/o:buffalo:wzr-1750dhp2_firmware';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140996");
  script_version("2019-05-24T11:20:30+0000");
  script_tag(name:"last_modification", value:"2019-05-24 11:20:30 +0000 (Fri, 24 May 2019)");
  script_tag(name:"creation_date", value:"2018-04-18 14:09:34 +0700 (Wed, 18 Apr 2018)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2018-0554", "CVE-2018-0555", "CVE-2018-0556");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Buffalo WZR-1750DHP2 < 2.31 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_buffalo_airstation_detect.nasl");
  script_mandatory_keys("buffalo_airstation/detected");

  script_tag(name:"summary", value:"Buffalo WZR-1750DHP2 is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Buffalo WZR-1750DHP2 is prone to multiple vulnerabilities:

  - bypass of authentication and executing arbitrary commands on the device via unspecified vectors. (CVE-2018-0554)

  - executing arbitrary code via a specially crafted file. (CVE-2018-0555)

  - executing arbitrary OS commands via unspecified vectors. (CVE-2018-0556");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Buffalo WZR-1750DHP2 firmware version 2.30 and prior.");

  script_tag(name:"solution", value:"Update to firmware version 2.31 or later.");

  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN93397125/index.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.31");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

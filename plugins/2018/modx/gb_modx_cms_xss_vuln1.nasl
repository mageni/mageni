###############################################################################
# OpenVAS Vulnerability Test
#
# MODX Revolution <= 2.6.5 XSS Vulnerability
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

CPE = "cpe:/a:modx:revolution";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141542");
  script_version("2019-04-26T13:30:35+0000");
  script_tag(name:"last_modification", value:"2019-04-26 13:30:35 +0000 (Fri, 26 Apr 2019)");
  script_tag(name:"creation_date", value:"2018-10-01 16:49:26 +0700 (Mon, 01 Oct 2018)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2018-17556");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MODX Revolution < 2.7.1 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_modx_cms_detect.nasl");
  script_mandatory_keys("modx_cms/installed");

  script_tag(name:"summary", value:"MODX Revolution allows stored XSS via a Create New Media Source action.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"MODX Revolution prior to 2.7.1.");

  script_tag(name:"solution", value:"Update to version 2.7.1 or later.");

  script_xref(name:"URL", value:"https://github.com/modxcms/revolution/issues/14094");
  script_xref(name:"URL", value:"https://github.com/modxcms/revolution/pull/14335");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
path = infos['location'];

if (version_is_less(version: version, test_version: "2.7.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.7.1", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

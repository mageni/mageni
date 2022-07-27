# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:xwiki:xwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124011");
  script_version("2022-02-24T14:03:33+0000");
  script_tag(name:"last_modification", value:"2022-02-24 14:03:33 +0000 (Thu, 24 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-11 12:04:03 +0000 (Fri, 11 Feb 2022)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-16 15:15:00 +0000 (Wed, 16 Feb 2022)");

  script_cve_id("CVE-2022-23620");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XWiki File Write Vulnerability (GHSA-7ph6-5cmq-xgjq)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"summary", value:"XWiki is prone to a file write vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present  on the target host.");

  script_tag(name:"insight", value:"AbstractSxExportURLFactoryActionHandler#processSx does not
  escape anything from SSX document reference when serializing it on filesystem, so it's easy to
  mess up the HTML or PDF export process with reference elements containing filesystem syntax like
  '../', './'. or '/' in general (the last two not causing any security threat, but can cause
  conflicts with others serialized files).");

  script_tag(name:"affected", value:"XWiki version 6.2 and later.");

  script_tag(name:"solution", value:"Update to version 13.6RC1 or later.");

  script_xref(name:"URL", value:"https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-7ph6-5cmq-xgjq");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "6.2", test_version_up: "13.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "13.6-rc-1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

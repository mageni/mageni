# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:docker:docker";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112983");
  script_version("2021-09-09T08:01:35+0000");
  script_tag(name:"last_modification", value:"2021-09-09 10:21:25 +0000 (Thu, 09 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-08 08:04:11 +0000 (Wed, 08 Sep 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-31 14:15:00 +0000 (Mon, 31 Aug 2020)");

  script_cve_id("CVE-2014-0047", "CVE-2014-0048");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Docker < 1.5.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_docker_http_rest_api_detect.nasl", "gb_docker_ssh_login_detect.nasl");
  script_mandatory_keys("docker/version");

  script_tag(name:"summary", value:"Docker is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2014-0047: Docker allows local users to have unspecified impact via vectors involving
  unsafe /tmp usage.

  - CVE-2014-0048: Some programs and scripts in Docker are downloaded via HTTP and then executed
  or used in unsafe ways.");

  script_tag(name:"affected", value:"Docker prior to version 1.5.0.");

  script_tag(name:"solution", value:"Update to version 1.5.0 or later.");

  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2015/03/24/23");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1063549");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2015/03/24/18");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2015/03/24/22");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "1.5.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.5.0");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

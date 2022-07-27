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

CPE = "cpe:/a:gogs:gogs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127007");
  script_version("2022-05-12T12:54:27+0000");
  script_tag(name:"last_modification", value:"2022-05-13 10:17:58 +0000 (Fri, 13 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-09 13:49:29 +0000 (Mon, 09 May 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2022-1464");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Gogs < 0.12.7 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_gogs_http_detect.nasl");
  script_mandatory_keys("gogs/detected");

  script_tag(name:"summary", value:"Gogs is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An attacker is able to upload a HTML file to a repository with
  an XSS payload inside.

  When any user view the repository and click the attachment link then the XSS is executed. If the
  repository is public any user can view the report and when opening the attachment then the XSS is
  executed.

  This bug allows the execution of any JavaScript code in the victim account.");

  script_tag(name:"affected", value:"Gogs prior to version 0.12.7.");

  script_tag(name:"solution", value:"Update to version 0.12.7 or later.");

  script_xref(name:"URL", value:"https://github.com/gogs/gogs/commit/bc77440b301ac8780698be91dff1ac33b7cee850");
  script_xref(name:"URL", value:"https://github.com/gogs/gogs/issues/6919");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/34a12146-3a5d-4efc-a0f8-7a3ae04b198d");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "0.12.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.12.7");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

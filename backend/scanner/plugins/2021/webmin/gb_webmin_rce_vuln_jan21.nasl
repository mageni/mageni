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

CPE = "cpe:/a:webmin:webmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145164");
  script_version("2021-01-15T04:55:42+0000");
  script_tag(name:"last_modification", value:"2021-01-15 11:06:40 +0000 (Fri, 15 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-15 04:39:01 +0000 (Fri, 15 Jan 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2020-35769");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Webmin < 1.970 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("webmin.nasl", "os_detection.nasl");
  script_mandatory_keys("webmin/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"miniserv.pl in Webmin on Windows mishandles special characters in query arguments to the CGI program.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Webmin version 1.962 and probably prior.");

  script_tag(name:"solution", value:"Update to version 1.970 or later.");

  script_xref(name:"URL", value:"https://github.com/webmin/webmin/commit/1163f3a7f418f249af64890f4636575e687e9de7#diff-9b33fd8f5603d4f0d1428689bc36f24af4770608a22c0d92b7a8bcc522450dc6");

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

if (version_is_less(version: version, test_version: "1.970")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.970", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

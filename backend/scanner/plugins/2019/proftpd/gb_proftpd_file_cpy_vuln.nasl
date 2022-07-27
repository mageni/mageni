# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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

CPE = "cpe:/a:proftpd:proftpd";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142662");
  script_version("2019-07-24T05:45:03+0000");
  script_tag(name:"last_modification", value:"2019-07-24 05:45:03 +0000 (Wed, 24 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-24 03:20:49 +0000 (Wed, 24 Jul 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-12815");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("ProFTPD <= 1.3.6 'mod_copy' Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("secpod_proftpd_server_detect.nasl");
  script_mandatory_keys("ProFTPD/Installed");

  script_tag(name:"summary", value:"An arbitrary file copy vulnerability in mod_copy in ProFTPD allows for remote
  code execution and information disclosure without authentication, a related issue to CVE-2015-3306.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"ProFTPD version 1.3.6 and prior.");

  script_tag(name:"solution", value:"As a workaround disable mod_copy in the ProFTPd configuration file.");

  script_xref(name:"URL", value:"https://tbspace.de/cve201912815proftpd.html");
  script_xref(name:"URL", value:"http://bugs.proftpd.org/show_bug.cgi?id=4372");
  script_xref(name:"URL", value:"https://www.bleepingcomputer.com/news/security/proftpd-vulnerability-lets-users-copy-files-without-permission/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "1.3.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

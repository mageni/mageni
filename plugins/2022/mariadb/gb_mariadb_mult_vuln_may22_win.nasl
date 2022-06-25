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

CPE = "cpe:/a:mariadb:mariadb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127027");
  script_version("2022-06-03T03:04:26+0000");
  script_tag(name:"last_modification", value:"2022-06-03 10:37:36 +0000 (Fri, 03 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-05-31 09:47:15 +0000 (Tue, 31 May 2022)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-28 02:39:00 +0000 (Sat, 28 May 2022)");

  script_cve_id("CVE-2022-31621", "CVE-2022-31622", "CVE-2022-31623", "CVE-2022-31624");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MariaDB < 10.7 Multiple Vulnerabilities (May 2022) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("mysql_version.nasl", "os_detection.nasl");
  script_mandatory_keys("MariaDB/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"MariaDB is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-31621: In extra/mariabackup/ds_xbstream.cc, while executing the method xbstream_open,
  the held lock is not released correctly, which allows local users to trigger a denial of service
  due to the deadlock.

  - CVE-2022-31622: in extra/mariabackup/ds_compress.cc, while executing the method
  create_worker_threads, the held lock is not released correctly, which allows local users
  to trigger a denial of service due to the deadlock,

  - CVE-2022-31623: In extra/mariabackup/ds_compress.cc, while executing the method
  create_worker_threads, the held lock thd->ctrl_mutex is not released correctly, which allows
  local users to trigger a denial of service due to the deadlock.

  - CVE-2022-31624: While executing the plugin/server_audit/server_audit.c method log_statement_ex,
  the held lock lock_bigbuffer is not released correctly, which allows local users to trigger
  a denial of service due to the deadlock.");

  script_tag(name:"affected", value:"MariaDB prior to version 10.7.");

  script_tag(name:"solution", value:"Update to version 10.7 or later.");

  script_xref(name:"URL", value:"https://github.com/MariaDB/server/commit/b1351c15946349f9daa7e5297fb2ac6f3139e4a8");
  script_xref(name:"URL", value:"https://github.com/MariaDB/server/commit/e1eb39a446c30b8459c39fd7f2ee1c55a36e97d2");
  script_xref(name:"URL", value:"https://github.com/MariaDB/server/commit/7c30bc38a588b22b01f11130cfe99e7f36accf94");
  script_xref(name:"URL", value:"https://github.com/MariaDB/server/commit/d627d00b13ab2f2c0954ea7b77202470cb102944");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit( 0 );

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "10.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

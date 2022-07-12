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

CPE = "cpe:/a:monsta:ftp";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126040");
  script_version("2022-06-21T15:24:48+0000");
  script_tag(name:"last_modification", value:"2022-06-21 15:24:48 +0000 (Tue, 21 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-06-15 10:15:33 +0000 (Wed, 15 Jun 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-08 13:18:00 +0000 (Wed, 08 Jul 2020)");

  script_cve_id("CVE-2020-14055", "CVE-2020-14056", "CVE-2020-14057");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MonstaFTP < 2.10.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_monsta_ftp_detect.nasl");
  script_mandatory_keys("Monsta-FTP-master/Installed");

  script_tag(name:"summary", value:"MonstaFTP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"impact", value:"The following vulnerabilities exist:

  - CVE-2020-14055: An attacker can store JavaScript code on the server, which might lead to
  information leakage like FTP credentials and can also affect other applications  running within
  the same origin.

  - CVE-2020-14056: An attacker can read arbitrary local files accessible by the webserver by
  exploiting this vulnerability. It might lead to information leakage from or manipulation of
  internal services.

  - CVE-2020-14057: An attacker can read and write arbitrary local files accessible by the webserver
  by exploiting the vulnerability. This might gain remote code execution by uploading PHP scripts in
  the web root and calling it via the webserver.");

  script_tag(name:"affected", value:"MonstaFTP version 2.10.1 and prior.");

  script_tag(name:"solution", value:"Update to version 2.10.2 or later.");

  script_xref(name:"URL", value:"https://www.monstaftp.com/notes/");
  script_xref(name:"URL", value:"https://www.sba-research.org/2020/07/01/security-advisories-news-monsta-ftp-2-10-1-cve-2020-14057-cve-2020-14056-cve-2020-14055/");
  script_xref(name:"URL", value:"https://github.com/sbaresearch/advisories/tree/public/2019/SBA-ADV-20191211-01_Monsta_FTP_Stored_XSS");
  script_xref(name:"URL", value:"https://github.com/sbaresearch/advisories/tree/public/2019/SBA-ADV-20191203-02_Monsta_FTP_Server-Side_Request_Forgery");
  script_xref(name:"URL", value:"https://github.com/sbaresearch/advisories/tree/public/2019/SBA-ADV-20191203-01_Monsta_FTP_Arbitrary_File_Read_and_Write");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "2.10.2")) {
  report = report_fixed_ver(installed_version:version, fixed_version: "2.10.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

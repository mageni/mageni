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

CPE = "cpe:/a:eyes_of_network:eyes_of_network";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126126");
  script_version("2022-08-29T08:42:23+0000");
  script_tag(name:"last_modification", value:"2022-08-29 08:42:23 +0000 (Mon, 29 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-26 09:32:02 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-11 18:35:00 +0000 (Mon, 11 Jul 2022)");

  script_cve_id("CVE-2021-40643");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # Cacti patch shipped separately

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Eyes Of Network (EON) <= 5.3 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_eyesofnetwork_detect.nasl");
  script_mandatory_keys("eyesofnetwork/detected");

  script_tag(name:"summary", value:"Eyes Of Network (EON) is prone to a remote code execution
  (RCE) vulnerability on the mail options configuration page.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In the location of the 'sendmail' application in the 'cacti'
  configuration page (by default/usr/sbin/sendmail) it is possible to execute any command, which
  will be executed when we make a test of the configuration ('send test mail').");

  script_tag(name:"impact", value:"An attacker may obtain a shell with root rights on an instance
  of EON without prior information or login.");

  script_tag(name:"affected", value:"Eyes Of Network version 5.3 and prior.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.eyesofnetwork.com/en/news/vulnerabilite-cacti");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "5.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

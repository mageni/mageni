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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2012.98");
  script_cve_id("CVE-2012-4206");
  script_tag(name:"creation_date", value:"2021-11-16 11:08:07 +0000 (Tue, 16 Nov 2021)");
  script_version("2021-11-16T11:08:07+0000");
  script_tag(name:"last_modification", value:"2021-11-16 11:08:07 +0000 (Tue, 16 Nov 2021)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Mozilla Firefox Security Advisory (MFSA2012-98) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2012-98");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-98/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=792106");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Firefox installer DLL hijacking
Security researcher Robert Kugler reported that when a specifically named DLL file on a Windows computer is placed in the default downloads directory with the Firefox installer, the Firefox installer will load this DLL when it is launched. In circumstances where the installer is run by an administrator privileged account, this allows for the downloaded DLL file to be run with administrator privileges. This can lead to arbitrary code execution from a privileged account.");

  script_tag(name:"affected", value:"Firefox version(s) below 17 and below 18.");

  script_tag(name:"solution", value:"The vendor has released an update. Please see the reference(s) for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "17", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

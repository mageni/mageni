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
  script_oid("1.3.6.1.4.1.25623.1.0.818175");
  script_version("2021-08-03T06:52:21+0000");
  script_cve_id("CVE-2021-29970", "CVE-2021-30547", "CVE-2021-29972", "CVE-2021-29974",
                "CVE-2021-29975", "CVE-2021-29976", "CVE-2021-29977");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-08-03 10:35:54 +0000 (Tue, 03 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-07-28 15:39:44 +0530 (Wed, 28 Jul 2021)");
  script_name("Mozilla Firefox Security Updates(mfsa_2021-28_2021-30)-MAC OS X");

  script_tag(name:"summary", value:"This host is missing a security update
  according to Mozilla.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Use-after-free in accessibility features of a document.

  - Out of bounds write in ANGLE.

  - Use of out-of-date library included use-after-free vulnerability.

  - HSTS errors could be overridden when network partitioning was enabled.

  - Text message could be overlaid on top of another website.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code and cause a denial of service on affected system.");
  script_tag(name:"affected", value:"Mozilla Firefox version before 90 on MAC OS X.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 90
  or later. Please see the references for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-28/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"90"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"90", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);

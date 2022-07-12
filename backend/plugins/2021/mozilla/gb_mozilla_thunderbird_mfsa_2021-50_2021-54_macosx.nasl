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

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818880");
  script_version("2021-12-21T14:03:30+0000");
  script_cve_id("CVE-2021-43528", "CVE-2021-43546", "CVE-2021-43545", "CVE-2021-43543",
                "CVE-2021-43542", "CVE-2021-43541", "CVE-2021-43539", "CVE-2021-43538",
                "CVE-2021-43537", "CVE-2021-43536");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-12-22 11:14:08 +0000 (Wed, 22 Dec 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-10 16:44:00 +0000 (Fri, 10 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-12 23:55:27 +0530 (Sun, 12 Dec 2021)");
  script_name("Mozilla Thunderbird Security Updates(mfsa_2021-50_2021-54)-Mac OS X");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - URL leakage when navigating while executing asynchronous function.

  - Heap buffer overflow when using structured clone.

  - Missing fullscreen and pointer lock notification when requesting both.

  - GC rooting failure when calling wasm instance methods.

  - External protocol handler parameters were unescaped

  - XMLHttpRequest error codes could have leaked the existence of an external protocol handler.

  - Bypass of CSP sandbox directive when embedding.

  - Denial of Service when using the Location API in a loop.

  - Cursor spoofing could overlay user interface when native cursor is zoomed.

  - JavaScript unexpectedly enabled for the composition area.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, bypass security restrictions, conduct spoofing
  and cause a denial of service on affected system.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before
  91.4 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 91.4
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-54/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Thunderbird/MacOSX/Version");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"91.4"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"91.4", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);

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

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826440");
  script_version("2022-09-08T10:11:29+0000");
  script_cve_id("CVE-2022-3033", "CVE-2022-3032", "CVE-2022-3034", "CVE-2022-36059");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-09-08 10:11:29 +0000 (Thu, 08 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-06 11:23:37 +0530 (Tue, 06 Sep 2022)");
  script_name("Mozilla Thunderbird Security Update(mfsa2022-38) - Windows");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Leaking of sensitive information when composing a response to an HTML email
  with a META refresh tag.

  - Remote content specified in an HTML document that was nested inside an
  iframe's srcdoc attribute was not blocked.

  - An iframe element in an HTML email could trigger a network request.

  - Matrix SDK bundled with Thunderbird vulnerable to denial-of-service attack.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, disclose information, conduct spoofing
  and cause a denial of service on affected system.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before
  102.2.1 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version
  102.2.1 or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-38");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"102.2.1"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"102.2.1", install_path:path);
  security_message(data:report);
  exit(0);
}

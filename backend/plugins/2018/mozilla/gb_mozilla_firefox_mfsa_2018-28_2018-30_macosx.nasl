###############################################################################
# OpenVAS Vulnerability Test
# Id$
#
# Mozilla Firefox Security Updates(mfsa_2018-28_2018-30)-MAC OS X
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814621");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-12407", "CVE-2018-17466", "CVE-2018-18492", "CVE-2018-18493",
                "CVE-2018-18494", "CVE-2018-18495", "CVE-2018-12405", "CVE-2018-18497",
                "CVE-2018-18498", "CVE-2018-12406");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-12-13 11:21:59 +0530 (Thu, 13 Dec 2018)");
  script_name("Mozilla Firefox Security Updates( mfsa_2018-28_2018-30 )-MAC OS X");

  script_tag(name:"summary", value:"This host is installed with Mozilla Firefox
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Check if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - A buffer overflow error with ANGLE library when using VertexBuffer11 module.

  - Buffer overflow and out-of-bounds read in ANGLE library with TextureStorage11.

  - An use-after-free error with select element.

  - A buffer overflow error in accelerated 2D canvas with Skia.

  - Same-origin policy violation using location attribute and performance.getEntries
    to steal cross-origin URLs.

  - WebExtension content scripts can be loaded in about, in violation of the
    permissions granted to extensions.

  - WebExtensions can load arbitrary URLs through pipe separators.

  - An integer overflow error when calculating buffer sizes for images.");

  script_tag(name:"impact", value:"Successful exploitation allow attackers
  to run arbitrary code, escalate privileges and bypass security restrictions.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 64 on MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 64
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-29/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
ffVer = infos['version'];
ffPath = infos['location'];

if(version_is_less(version:ffVer, test_version:"64.0"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"64.0", install_path:ffPath);
  security_message(data:report);
  exit(0);
}
exit(99);

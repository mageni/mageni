###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Thunderbird Security Updates(mfsa_2018-04_2018-04)-MAC OS X
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

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813050");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-5095", "CVE-2018-5096", "CVE-2018-5097", "CVE-2018-5098",
                "CVE-2018-5099", "CVE-2018-5102", "CVE-2018-5103", "CVE-2018-5104",
                "CVE-2018-5117", "CVE-2018-5089");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-03-22 11:48:22 +0530 (Thu, 22 Mar 2018)");
  script_name("Mozilla Thunderbird Security Updates(mfsa_2018-04_2018-04)-MAC OS X");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Thunderbird and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An integer overflow error in Skia library during edge builder allocation.

  - An use-after-free error while editing form elements.

  - An use-after-free error when source document is manipulated during XSLT.

  - An use-after-free error while manipulating form input elements.

  - An use-after-free error with widget listener.

  - An use-after-free error when manipulating HTML media elements.

  - An use-after-free error during mouse event handling.

  - An use-after-free error during font face manipulation.

  - An url spoofing with right-to-left text aligned left-to-right.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to bypass security restrictions and perform unauthorized
  actions, conduct spoofing attack, and execute arbitrary code in the
  context of the affected application.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before 52.6 on MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 52.6");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-04");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("ThunderBird/MacOSX/Version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/thunderbird");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
tbVer = infos['version'];
tbPath = infos['location'];

if(version_is_less(version:tbVer, test_version:"52.6"))
{
  report = report_fixed_ver(installed_version:tbVer, fixed_version:"52.6", install_path:tbPath);
  security_message(data:report);
  exit(0);
}
exit(0);

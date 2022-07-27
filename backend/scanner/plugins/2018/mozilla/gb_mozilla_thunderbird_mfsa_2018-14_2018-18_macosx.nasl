###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Thunderbird Security Updates(mfsa_2018-14_2018-18)-MAC OS X
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.813550");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-12359", "CVE-2018-12360", "CVE-2018-12372", "CVE-2018-12373",
                "CVE-2018-12362", "CVE-2018-12363", "CVE-2018-12364", "CVE-2018-12365",
                "CVE-2018-12366", "CVE-2018-12368", "CVE-2018-12374", "CVE-2018-5188");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-07-04 12:05:34 +0530 (Wed, 04 Jul 2018)");
  script_name("Mozilla Thunderbird Security Updates( mfsa_2018-14_2018-18 )-MAC OS X");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Thunderbird and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to -

  - Buffer overflow error while using computed size of canvas element.

  - Use-after-free error when using focus()

  - Allowing S/MIME and PGP decryption oracles to be built with HTML emails.

  - S/MIME plaintext can be leaked through HTML reply/forward.

  - Integer overflow error in SSSE3 scaler.

  - Use-after-free error when appending DOM nodes.

  - CSRF vulnerabilities in 307 redirects and NPAPI.

  - Compromised IPC child process can list local filenames.

  - Invalid data handling during QCMS transformations.

  - No warning when opening executable SettingContent-ms files.

  - Using form to exfiltrate encrypted mail part by pressing enter in form field.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to crash the application, leak plaintext, perform cross-site request forgery
  attacks, expose of private local files, leak private data into the output and
  execute arbitrary code.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before
  52.9 on MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 52.9. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-18");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/thunderbird");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("ThunderBird/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
tbVer = infos['version'];
tbPath = infos['location'];

if(version_is_less(version:tbVer, test_version:"52.9"))
{
  report = report_fixed_ver(installed_version:tbVer, fixed_version:"52.9", install_path:tbPath);
  security_message(data:report);
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_thunderbird_mfsa_2017-23_2017-23_macosx.nasl 11983 2018-10-19 10:04:45Z mmartin $
#
# Mozilla Thunderbird Security Updates( mfsa_2017-23_2017-23 )-MAC OS X
#
# Authors:
# kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.811941");
  script_version("$Revision: 11983 $");
  script_cve_id("CVE-2017-7793", "CVE-2017-7818", "CVE-2017-7819", "CVE-2017-7824",
		"CVE-2017-7805", "CVE-2017-7814", "CVE-2017-7825", "CVE-2017-7823",
		"CVE-2017-7810");
  script_bugtraq_id(101055, 101053, 101059, 101054);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-12 11:11:21 +0530 (Thu, 12 Oct 2017)");
  script_name("Mozilla Thunderbird Security Updates( mfsa_2017-23_2017-23 )-MAC OS X");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Thunderbird and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws exist due to,

  - Use-after-free with Fetch API.

  - Use-after-free during ARIA array manipulation.

  - Use-after-free while resizing images in design mode.

  - Buffer overflow when drawing and validating elements with ANGLE.

  - Use-after-free in TLS 1.2 generating handshake hashes.

  - Blob and data URLs bypass phishing and malware protection warnings.

  - OS X fonts render some Tibetan and Arabic unicode characters as spaces.

  - CSP sandbox directive did not create a unique origin.

  - Memory safety bugs fixed in Thunderbird 52.4");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to gain access to potentially sensitive information,
  execute arbitrary code and conduct a denial-of-service condition.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before 52.4 on MAC OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 52.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-23/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("ThunderBird/MacOSX/Version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/thunderbird");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!tbVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:tbVer, test_version:"52.4"))
{
  report = report_fixed_ver(installed_version:tbVer, fixed_version:"52.4");
  security_message(data:report);
  exit(0);
}

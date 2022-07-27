###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_thunderbird_mfsa_2017-17_2017-17_win.nasl 11982 2018-10-19 08:49:21Z mmartin $
#
# Mozilla Thunderbird Security Updates( mfsa_2017-17_2017-17 )-Windows
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.811186");
  script_version("$Revision: 11982 $");
  script_cve_id("CVE-2017-5472", "CVE-2017-7749", "CVE-2017-7750", "CVE-2017-7751",
                "CVE-2017-7752", "CVE-2017-7754", "CVE-2017-7756", "CVE-2017-7757",
                "CVE-2017-7778", "CVE-2017-7771", "CVE-2017-7772", "CVE-2017-7773",
                "CVE-2017-7774", "CVE-2017-7775", "CVE-2017-7776", "CVE-2017-7777",
                "CVE-2017-7758", "CVE-2017-7763", "CVE-2017-7764", "CVE-2017-7765",
                "CVE-2017-5470");
  script_bugtraq_id(99040, 99057, 99041);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 10:49:21 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-15 19:01:05 +0530 (Thu, 15 Jun 2017)");
  script_name("Mozilla Thunderbird Security Updates( mfsa_2017-17_2017-17 )-Windows");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Thunderbird and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws exist due to,

  - Use-after-free using destroyed node when regenerating trees.

  - Use-after-free during docshell reloading.

  - Use-after-free with track elements.

  - Use-after-free with content viewer listeners.

  - Use-after-free with IME input.

  - Out-of-bounds read in WebGL with ImageInfo object.

  - Use-after-free and use-after-scope logging XHR header errors.

  - Use-after-free in IndexedDB.

  - Vulnerabilities in the Graphite 2 library.

  - Out-of-bounds read in Opus encoder.

  - Mac fonts render some unicode characters as spaces.

  - Domain spoofing with combination of Canadian Syllabics and other unicode blocks.

  - Mark of the Web bypass when saving executable files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code, to delete arbitrary files by leveraging
  certain local file execution, to obtain sensitive information, and to cause
  a denial of service.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before 52.2 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 52.2");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-17/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/thunderbird");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!tbVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:tbVer, test_version:"52.2"))
{
  report = report_fixed_ver(installed_version:tbVer, fixed_version:"52.2");
  security_message(data:report);
  exit(0);
}

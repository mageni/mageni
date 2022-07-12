###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_mfsa_2017-15_2017-16_win.nasl 11888 2018-10-12 15:27:49Z cfischer $
#
# Mozilla Firefox Security Updates( mfsa_2017-15_2017-16 )-Windows
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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811197");
  script_version("$Revision: 11888 $");
  script_cve_id("CVE-2017-5472", "CVE-2017-7749", "CVE-2017-7750", "CVE-2017-7751",
		"CVE-2017-7752", "CVE-2017-7754", "CVE-2017-7755", "CVE-2017-7756",
		"CVE-2017-7757", "CVE-2017-7778", "CVE-2017-7771", "CVE-2017-7772",
		"CVE-2017-7773", "CVE-2017-7774", "CVE-2017-7775", "CVE-2017-7776",
		"CVE-2017-7777", "CVE-2017-7758", "CVE-2017-5470", "CVE-2017-7760",
		"CVE-2017-7761", "CVE-2017-7762", "CVE-2017-7763", "CVE-2017-7764",
		"CVE-2017-7765", "CVE-2017-7766", "CVE-2017-7767", "CVE-2017-7768",
		"CVE-2017-5471");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 17:27:49 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-15 17:23:01 +0530 (Thu, 15 Jun 2017)");
  script_name("Mozilla Firefox Security Updates( mfsa_2017-15_2017-16 )-Windows");

  script_tag(name:"summary", value:"This host is installed with Mozilla Firefox
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws exists due to,

  - Use-after-free using destroyed node when regenerating trees.

  - Use-after-free during docshell reloading.

  - Use-after-free with track elements.

  - Use-after-free with content viewer listeners.

  - Use-after-free with IME input.

  - Out-of-bounds read in WebGL with ImageInfo object.

  - Privilege escalation through Firefox Installer with same directory DLL files.

  - Use-after-free and use-after-scope logging XHR header errors.

  - Use-after-free in IndexedDB.

  - Vulnerabilities in the Graphite 2 library.

  - Out-of-bounds read in Opus encoder.

  - Android intent URLs can cause navigation to local file system.

  - File manipulation and privilege escalation via callback parameter in Mozilla
    Windows Updater and Maintenance Service.

  - File deletion and privilege escalation through Mozilla Maintenance Service
    helper.exe application.

  - Addressbar spoofing in Reader mode.

  - Mac fonts render some unicode characters as spaces.

  - Domain spoofing with combination of Canadian Syllabics and other unicode blocks.

  - Mark of the Web bypass when saving executable files.

  - File execution and privilege escalation through updater.ini, Mozilla Windows
    Updater, and Mozilla Maintenance Service.

  - Privilege escalation and arbitrary file overwrites through Mozilla Windows
    Updater and Mozilla Maintenance Service.

  - 32 byte arbitrary file read through Mozilla Maintenance Service.

  - Addressbar spoofing with JavaScript events and fullscreen mode.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code, to delete arbitrary files by leveraging
  certain local file execution, to obtain sensitive information, and to cause
  a denial of service.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 54.0 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 54
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-15");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/firefox/all.html");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
   exit(0);
}

if(version_is_less(version:ffVer, test_version:"54.0"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"54.0");
  security_message(data:report);
  exit(0);
}

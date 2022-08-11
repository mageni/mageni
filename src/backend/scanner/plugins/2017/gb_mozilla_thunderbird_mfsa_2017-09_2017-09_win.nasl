###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_thunderbird_mfsa_2017-09_2017-09_win.nasl 11888 2018-10-12 15:27:49Z cfischer $
#
# Mozilla Thunderbird Security Updates( mfsa_2017-09_2017-09 )-Windows
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
  script_oid("1.3.6.1.4.1.25623.1.0.810837");
  script_version("$Revision: 11888 $");
  script_cve_id("CVE-2017-5400", "CVE-2017-5401", "CVE-2017-5402", "CVE-2017-5403",
		"CVE-2017-5404", "CVE-2017-5406", "CVE-2017-5407", "CVE-2017-5410",
		"CVE-2017-5411", "CVE-2017-5408", "CVE-2017-5412", "CVE-2017-5413",
		"CVE-2017-5414", "CVE-2017-5416", "CVE-2017-5398", "CVE-2017-5399",
		"CVE-2017-5418", "CVE-2017-5419", "CVE-2017-5405", "CVE-2017-5421",
		"CVE-2017-5422");
  script_bugtraq_id(96654, 96677, 96664, 96691, 96692, 96693, 96694, 96651);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 17:27:49 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-11 10:18:00 +0530 (Tue, 11 Apr 2017)");
  script_name("Mozilla Thunderbird Security Updates( mfsa_2017-09_2017-09 )-Windows");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Thunderbird and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws exist due to,

  - asm.js JIT-spray bypass of ASLR and DEP.

  - Memory Corruption when handling ErrorResult.

  - Use-after-free working with events in FontFace objects.

  - Use-after-free using addRange to add range to an incorrect root object.

  - Use-after-free working with ranges in selections.

  - Segmentation fault in Skia with canvas operations.

  - Pixel and history stealing via floating-point timing side channel with SVG filters.

  - Memory corruption during JavaScript garbage collection incremental sweeping.

  - Use-after-free in Buffer Storage in libGLES.

  - Cross-origin reading of video captions in violation of CORS.

  - Buffer overflow read in SVG filters.

  - Segmentation fault during bidirectional operations.

  - File picker can choose incorrect default directory.

  - Null dereference crash in HttpChannel.

  - Overly permissive Gecko Media Plugin sandbox regular expression access.

  - Gecko Media Plugin sandbox is not started if seccomp-bpf filter is running.

  - Out of bounds read when parsing HTTP digest authorization responses.

  - Repeated authentication prompts lead to DOS attack.

  - FTP response codes can cause use of uninitialized values for ports.

  - Print preview spoofing.

  - DOS attack by using view-source: protocol repeatedly in one hyperlink.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to execute arbitrary code, to delete arbitrary files
  by leveraging certain local file execution, to obtain sensitive information,
  and to cause a denial of service.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before 52.0 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 52.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-09");
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

if(version_is_less(version:tbVer, test_version:"52.0"))
{
  report = report_fixed_ver(installed_version:tbVer, fixed_version:"52.0");
  security_message(data:report);
  exit(0);
}

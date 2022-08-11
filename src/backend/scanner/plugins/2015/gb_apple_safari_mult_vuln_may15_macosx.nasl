###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_mult_vuln_may15_macosx.nasl 12391 2018-11-16 16:12:15Z cfischer $
#
# Apple Safari Multiple Vulnerabilities -01 May15 (Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805613");
  script_version("$Revision: 12391 $");
  script_cve_id("CVE-2015-1156", "CVE-2015-1155", "CVE-2015-1154", "CVE-2015-1153",
                "CVE-2015-1152");
  script_bugtraq_id(74527, 74526, 74525, 74524, 74523);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 17:12:15 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-05-11 14:59:28 +0530 (Mon, 11 May 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Apple Safari Multiple Vulnerabilities -01 May15 (Mac OS X)");

  script_tag(name:"summary", value:"This host is running Apple Safari and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - A flaw in WebKit in the handling of rel attributes in anchor elements which
    is triggered when clicking a link to visit a specially crafted web page.

  - A state management flaw in WebKit that is triggered as user-supplied input
    is not properly validated.

  - multiple flaws in WebKit that are triggered as user-supplied input is not
    properly validated.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  context-dependent attacker can potentially execute arbitrary code, can gain
  access to potentially sensitive user information from the file system, to
  spoof the user interface.");

  script_tag(name:"affected", value:"Apple Safari versions before 6.2.6, 7.x
  before 7.1.6 and 8.x before 8.0.6");

  script_tag(name:"solution", value:"Upgrade to Apple Safari version 6.2.6 or
  7.1.6 or 8.0.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.apple.com/HT204826");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2015/May/msg00000.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");
  script_xref(name:"URL", value:"http://www.apple.com/support");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!safVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:safVer, test_version:"6.2.6"))
{
  fix = "6.2.6";
  VULN = TRUE;
}

if(version_in_range(version:safVer, test_version:"7.0", test_version2:"7.1.5"))
{
  fix = "7.1.6";
  VULN = TRUE;
}

if(version_in_range(version:safVer, test_version:"8.0", test_version2:"8.0.5"))
{
  fix = "8.0.6";
  VULN = TRUE;
}

if(VULN)
{
  report = 'Installed version: ' + safVer + '\n' +
           'Fixed version:     ' + fix + '\n';
  security_message(data:report);
  exit(0);
}

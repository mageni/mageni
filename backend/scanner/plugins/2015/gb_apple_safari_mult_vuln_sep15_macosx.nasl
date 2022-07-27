###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_mult_vuln_sep15_macosx.nasl 12391 2018-11-16 16:12:15Z cfischer $
#
# Apple Safari Multiple Vulnerabilities-01 Sep15 (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805968");
  script_version("$Revision: 12391 $");
  script_cve_id("CVE-2015-3729", "CVE-2015-3730", "CVE-2015-3731", "CVE-2015-3732",
                "CVE-2015-3733", "CVE-2015-3734", "CVE-2015-3735", "CVE-2015-3736",
                "CVE-2015-3737", "CVE-2015-3738", "CVE-2015-3739", "CVE-2015-3740",
                "CVE-2015-3741", "CVE-2015-3742", "CVE-2015-3743", "CVE-2015-3744",
                "CVE-2015-3745", "CVE-2015-3746", "CVE-2015-3747", "CVE-2015-3748",
                "CVE-2015-3749", "CVE-2015-3750", "CVE-2015-3751", "CVE-2015-3752",
                "CVE-2015-3753", "CVE-2015-3754", "CVE-2015-3755");
  script_bugtraq_id(76342, 76338, 76341, 76339, 76344);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 17:12:15 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-09-01 11:47:05 +0530 (Tue, 01 Sep 2015)");
  script_name("Apple Safari Multiple Vulnerabilities-01 Sep15 (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with Apple Safari
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists duu to,

  - Multiple memory corruption issues existed in WebKit.

  - An error existed in Content Security Policy report requests which would not
    honor HTTP Strict Transport Security.

  - An issue existed where websites with video controls would load images nested
    in object elements in violation of the website's Content Security Policy
    directive.

  - Two issues existed in how cookies were added to Content Security Policy report
    requests. Cookies were sent in cross-origin report requests in violation of the
    standard.

  - Images fetched through URLs that redirected to a data:image resource could have
    been exfiltrated cross-origin.

  - An issue existed in caching of HTTP authentication. Credentials entered in
    private browsing mode were carried over to regular browsing which would reveal
    parts of the user's private browsing history.

  - Navigating to a malformed URL may have allowed a malicious website to display
    an arbitrary URL.

  - A malicious website could open another site and prompt for user input without
    a way for the user to tell where the prompt came from.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct spoofing attack, unexpected application termination
  or arbitrary code execution, trigger plaintext requests to an origin under HTTP
  Strict Transport Security, load image out of accordance with Content Security
  Policy directive, gain access to sensitive information, exfiltrate image data
  cross-origin and reveal private browsing history.");

  script_tag(name:"affected", value:"Apple Safari versions before 6.2.8, 7.x
  before 7.1.8, and 8.x before 8.0.8");

  script_tag(name:"solution", value:"Upgrade to Apple Safari version 6.2.8 or
  7.1.8 or 8.0.8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT205033");

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

if(version_is_less(version:safVer, test_version:"6.2.8"))
{
  fix = "6.2.8";
  VULN = TRUE;
}

if(version_in_range(version:safVer, test_version:"7.0", test_version2:"7.1.7"))
{
  fix = "7.1.8";
  VULN = TRUE;
}

if(version_in_range(version:safVer, test_version:"8.0", test_version2:"8.0.7"))
{
  fix = "8.0.8";
  VULN = TRUE;
}

if(VULN)
{
  report = 'Installed version: ' + safVer + '\n' +
           'Fixed version:     ' + fix + '\n';
  security_message(data:report);
  exit(0);
}

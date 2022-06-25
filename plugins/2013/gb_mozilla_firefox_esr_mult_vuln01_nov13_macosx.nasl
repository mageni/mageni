###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_esr_mult_vuln01_nov13_macosx.nasl 31965 2013-11-07 18:47:17Z nov$
#
# Mozilla Firefox ESR Multiple Vulnerabilities-01 Nov13 (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804137");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-5603", "CVE-2013-5598", "CVE-2013-5591", "CVE-2013-5593",
                "CVE-2013-5596");
  script_bugtraq_id(63416, 63419, 63417, 63429, 63420);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-11-07 12:28:51 +0530 (Thu, 07 Nov 2013)");
  script_name("Mozilla Firefox ESR Multiple Vulnerabilities-01 Nov13 (Mac OS X)");


  script_tag(name:"summary", value:"This host is installed with Mozilla Firefox ESR and is prone to multiple
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 24.1 or later.");
  script_tag(name:"insight", value:"Multiple flaws due to,

  - Use-after-free vulnerability in the
'nsContentUtils::ContentIsHostIncludingDescendantOf' function.

  - Improper handling of the appending of an IFRAME element in 'PDF.js'.

  - Unspecified vulnerabilities in the browser engine.

  - Improper restriction of the nature or placement of HTML within a dropdown menu.

  - Improper determination of the thread for release of an image object.");
  script_tag(name:"affected", value:"Mozilla Firefox ESR version 24.x before 24.1 on Mac OS X");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code,
cause a denial of service, spoof the address bar and conduct clickjacking
attacks.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55520/");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2013/mfsa2013-99.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox-ESR/MacOSX/Version");
  script_xref(name:"URL", value:"http://www.mozilla.org/en-US/firefox/organizations/all.html");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(ffVer && ffVer =~ "^24\.0")
{
  if(version_is_less(version:ffVer, test_version:"24.1"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

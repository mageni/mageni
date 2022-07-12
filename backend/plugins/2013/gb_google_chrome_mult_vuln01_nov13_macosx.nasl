###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln01_nov13_macosx.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Google Chrome Multiple Vulnerabilities Nov2013 (Mac OS X)
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
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

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803965");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-6621", "CVE-2013-6622", "CVE-2013-6623", "CVE-2013-6624",
                "CVE-2013-6625", "CVE-2013-6626", "CVE-2013-6627", "CVE-2013-6628",
                "CVE-2013-6629", "CVE-2013-6630", "CVE-2013-6631", "CVE-2013-2931");
  script_bugtraq_id(63667, 63669, 63671, 63670, 63672, 63674, 63675, 63678,
                    63676, 63679, 63673, 63677);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-11-19 16:43:17 +0530 (Tue, 19 Nov 2013)");
  script_name("Google Chrome Multiple Vulnerabilities Nov2013 (Mac OS X)");


  script_tag(name:"summary", value:"This host is installed with Google Chrome and is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to Google Chrome version 31.0.1650.48 or later.");
  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Use after free related to speech input elements

  - Use after free related to media elements

  - Out of bounds read in SVG

  - Use after free related to 'id' attribute strings

  - Use after free in DOM ranges

  - Address bar spoofing related to interstitial warnings

  - Out of bounds read in HTTP parsing

  - Issue with certificates not being checked during TLS renegotiation

  - Read of uninitialized memory in libjpeg and libjpeg-turbo");
  script_tag(name:"affected", value:"Google Chrome version prior to 31.0.1650.48 on Mac OS X");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of
service condition, information disclosure or possibly have other impact via
unknown vectors.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2013/11/stable-channel-update.html");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Nov/76");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!my_app_ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:my_app_ver, test_version:"31.0.1650.48"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

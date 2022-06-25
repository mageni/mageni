###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln01_oct13_win.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Google Chrome Multiple Vulnerabilities-01 Oct2013 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804105");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-2906", "CVE-2013-2923", "CVE-2013-2924", "CVE-2013-2922",
                "CVE-2013-2921", "CVE-2013-2907", "CVE-2013-2908", "CVE-2013-2909",
                "CVE-2013-2910", "CVE-2013-2911", "CVE-2013-2912", "CVE-2013-2913",
                "CVE-2013-2914", "CVE-2013-2919", "CVE-2013-2918", "CVE-2013-2917",
                "CVE-2013-2916", "CVE-2013-2915", "CVE-2013-2920");
  script_bugtraq_id(62752);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-10-07 14:27:23 +0530 (Mon, 07 Oct 2013)");
  script_name("Google Chrome Multiple Vulnerabilities-01 Oct2013 (Windows)");


  script_tag(name:"summary", value:"This host is installed with Google Chrome and is prone to multiple
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to version 30.0.1599.66 or later.");
  script_tag(name:"insight", value:"Multiple flaws exists, For more details refer the reference section.");
  script_tag(name:"affected", value:"Google Chrome version before 30.0.1599.66 on Windows");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of
service and to spoof the address bar or possibly have unspecified other
impacts via some known or unknown vectors.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55087");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61885");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/10/stable-channel-update.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!chromeVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"30.0.1599.66"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

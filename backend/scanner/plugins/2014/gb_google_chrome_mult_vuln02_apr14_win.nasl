###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln02_apr14_win.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Google Chrome Multiple Vulnerabilities - 02 Apr14 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804269");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-1730", "CVE-2014-1731", "CVE-2014-1732", "CVE-2014-1733",
                "CVE-2014-1734", "CVE-2014-1735", "CVE-2014-1736");
  script_bugtraq_id(67082);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-04-29 12:30:56 +0530 (Tue, 29 Apr 2014)");
  script_name("Google Chrome Multiple Vulnerabilities - 02 Apr14 (Windows)");


  script_tag(name:"summary", value:"The host is installed with Google Chrome and is prone to multiple
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaws are due to,

  - Multiple unspecified errors in V8.

  - A type confusion error exists in v8.

  - A type confusion error exists within DOM.

  - A use-after-free error exists in Speech Recognition.

  - An error exists related to compilation of Seccomp-BPF.

  - Some unspecified errors exist.

  - Integer overflow in api.cc in Google V8.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct a denial of
service, bypass intended sandbox restrictions, compromise a user's system
or an unknown impact.");
  script_tag(name:"affected", value:"Google Chrome version prior to 34.0.1847.131 on Windows.");
  script_tag(name:"solution", value:"Upgrade to Google Chrome 34.0.1847.131 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2014/04/stable-channel-update_24.html");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
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

if(version_is_less(version:chromeVer, test_version:"34.0.1847.131"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

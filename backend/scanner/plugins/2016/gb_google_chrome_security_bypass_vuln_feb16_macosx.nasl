###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_security_bypass_vuln_feb16_macosx.nasl 12455 2018-11-21 09:17:27Z cfischer $
#
# Google Chrome Security Bypass Vulnerability Feb16 (Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807084");
  script_version("$Revision: 12455 $");
  script_cve_id("CVE-2016-1629");
  script_bugtraq_id(83302);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-02-15 12:12:26 +0530 (Mon, 15 Feb 2016)");
  script_name("Google Chrome Security Bypass Vulnerability Feb16 (Mac OS X)");

  script_tag(name:"summary", value:"The host is installed with Google Chrome
  and is prone to security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in
  Same Origin Policy and a Sandbox protection.");

  script_tag(name:"impact", value:"Successful exploitation would allow remote
  attckers to bypass the same-origin policy and certain access restrictions to
  access data, or execute arbitrary script code and this could be used to steal
  sensitive information or launch other attacks.");

  script_tag(name:"affected", value:"Google Chrome versions prior to
  48.0.2564.116 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  48.0.2564.116 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2016/02/stable-channel-update_18.html");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!chromeVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"48.0.2564.116"))
{
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"48.0.2564.116");
  security_message(data:report);
  exit(0);
}

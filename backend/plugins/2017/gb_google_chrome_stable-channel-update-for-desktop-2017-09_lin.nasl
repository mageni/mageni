##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_stable-channel-update-for-desktop-2017-09_lin.nasl 11816 2018-10-10 10:42:56Z mmartin $
#
# Google Chrome Security Updates(stable-channel-update-for-desktop-2017-09)-Linux
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811805");
  script_version("$Revision: 11816 $");
  script_cve_id("CVE-2017-5111", "CVE-2017-5112", "CVE-2017-5113", "CVE-2017-5114",
                "CVE-2017-5115", "CVE-2017-5116", "CVE-2017-5117", "CVE-2017-5118",
                "CVE-2017-5119", "CVE-2017-5120");
  script_bugtraq_id(100610);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-10 12:42:56 +0200 (Wed, 10 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-09-07 11:46:45 +0530 (Thu, 07 Sep 2017)");
  script_name("Google Chrome Security Updates(stable-channel-update-for-desktop-2017-09)-Linux");

  script_tag(name:"summary", value:"The host is installed with Google Chrome
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws exists due to

  - An use after free error in PDFium.

  - A heap buffer overflow error in WebGL.

  - A heap buffer overflow error in Skia.

  - A Memory lifecycle issue in PDFium.

  - A type confusion error in V8.

  - Use of uninitialized value in Skia.

  - Bypass of Content Security Policy in Blink.

  - Potential HTTPS downgrade during redirect navigation.

  - Various fixes from internal audits, fuzzing and other initiatives.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities will allow remote attackers to execute arbitrary commands,
  corrupt memory and bypass security restrictions.");

  script_tag(name:"affected", value:"Google Chrome version
  prior to 61.0.3163.79 on Linux");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  61.0.3163.79 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2017/09/stable-channel-update-for-desktop.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!chr_ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chr_ver, test_version:"61.0.3163.79"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"61.0.3163.79");
  security_message(data:report);
  exit(0);
}

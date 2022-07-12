##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_stable-channel-update-for-desktop_13-2016-09_lin.nasl 11969 2018-10-18 14:53:42Z asteins $
#
# Google Chrome Security Updates(stable-channel-update-for-desktop_13-2016-09)-Linux
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
  script_oid("1.3.6.1.4.1.25623.1.0.809046");
  script_version("$Revision: 11969 $");
  script_cve_id("CVE-2016-5170", "CVE-2016-5171", "CVE-2016-5172", "CVE-2016-5173",
                "CVE-2016-5174", "CVE-2016-5175", "CVE-2016-7549", "CVE-2016-5176");
  script_bugtraq_id(92942, 93160, 93234);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 16:53:42 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-09-15 11:32:52 +0530 (Thu, 15 Sep 2016)");
  script_name("Google Chrome Security Updates(stable-channel-update-for-desktop_13-2016-09)-Linux");

  script_tag(name:"summary", value:"The host is installed with Google Chrome
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws exist due to,

  - Multiple use after free errors in Blink.

  - An arbitrary Memory Read error in v8

  - An extension resource access error.

  - The popup is not correctly suppressed.

  - Not ensuring that the recipient of a certain IPC message is a valid
    RenderFrame or RenderWidget.

  - An improper SafeBrowsing protection mechanism.

  - The various fixes from internal audits, fuzzing and other initiatives.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to corrupt memory, to bypass security,
  to reduce performance, to bypass the SafeBrowsing protection mechanism, to
  cause a denial of service and other unspecified impact.");

  script_tag(name:"affected", value:"Google Chrome version
  prior to 53.0.2785.113 on Linux");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  53.0.2785.113 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2016/09/stable-channel-update-for-desktop_13.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

if(version_is_less(version:chr_ver, test_version:"53.0.2785.113"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"53.0.2785.113");
  security_message(data:report);
  exit(0);
}
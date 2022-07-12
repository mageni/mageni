##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_stable-channel-update_28-2016-04_macosx.nasl 11969 2018-10-18 14:53:42Z asteins $
#
# Google Chrome Security Updates(stable-channel-update_28-2016-04)-MAC OS X
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
  script_oid("1.3.6.1.4.1.25623.1.0.807573");
  script_version("$Revision: 11969 $");
  script_cve_id("CVE-2016-1660", "CVE-2016-1661", "CVE-2016-1662", "CVE-2016-1663",
                "CVE-2016-1664", "CVE-2016-1665", "CVE-2016-1666", "CVE-2016-5168");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 16:53:42 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-05-02 14:07:18 +0530 (Mon, 02 May 2016)");
  script_name("Google Chrome Security Updates(stable-channel-update_28-2016-04)-MAC OS X");

  script_tag(name:"summary", value:"The host is installed with Google Chrome
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws exist due to

  - An out-of-bounds write error in Blink.

  - Memory corruption in cross-process frames.

  - An use-after-free error in extensions.

  - An Use-after-free error in Blink's V8 bindings.

  - Address bar spoofing vulnerability.

  - An information leak in V8.

  - The Various fixes from internal audits, fuzzing, and other initiatives.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow an unauthenticated, remote attacker to gain access
  to sensitive information, to execute arbitrary code, to cause a denial of
  service (DoS) condition and to conduct spoofing attacks on a targeted system.");

  script_tag(name:"affected", value:"Google Chrome version
  prior to 50.0.2661.94 on MAC OS X");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  50.0.2661.94 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2016/04/stable-channel-update_28.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  script_xref(name:"URL", value:"http://www.google.com/chrome");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!chr_ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chr_ver, test_version:"50.0.2661.94"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"50.0.2661.94");
  security_message(data:report);
  exit(0);
}

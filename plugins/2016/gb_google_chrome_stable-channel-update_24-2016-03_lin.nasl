##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_stable-channel-update_24-2016-03_lin.nasl 11969 2018-10-18 14:53:42Z asteins $
#
# Google Chrome Security Updates(stable-channel-update_24-2016-03)-Linux
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.807643");
  script_version("$Revision: 11969 $");
  script_cve_id("CVE-2016-1646", "CVE-2016-1647", "CVE-2016-1648", "CVE-2016-1649",
		        "CVE-2016-1650", "CVE-2016-3679");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 16:53:42 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-03-28 10:36:52 +0530 (Mon, 28 Mar 2016)");
  script_name("Google Chrome Security Updates(stable-channel-update_24-2016-03)-Linux");

  script_tag(name:"summary", value:"The host is installed with Google Chrome
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws exist due to,

  - Out-of-bounds read in V8.

  - Use-after-free in Navigation.

  - Use-after-free in Extensions.

  - Buffer overflow in libANGLE.

  - Various fixes from internal audits, fuzzing and other initiatives.

  - Multiple unspecified vulnerabilities in Google V8.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to execute arbitrary code in the context of the browser, obtain
  sensitive information, bypass security restrictions, or cause
  denial-of-service conditions.");

  script_tag(name:"affected", value:"Google Chrome version
  prior to 49.0.2623.108 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  49.0.2623.108 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2016/03/stable-channel-update_24.html");

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

if(version_is_less(version:chr_ver, test_version:"49.0.2623.108"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"49.0.2623.108");
  security_message(data:report);
  exit(0);
}

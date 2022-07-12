###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_imagemagick_mult_unspecified_vuln_win.nasl 12455 2018-11-21 09:17:27Z cfischer $
#
# ImageMagick Multiple Unspecified Vulnerabilities (Windows)
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

CPE = "cpe:/a:imagemagick:imagemagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810247");
  script_version("$Revision: 12455 $");
  script_cve_id("CVE-2016-5690", "CVE-2016-5691", "CVE-2016-5689");
  script_bugtraq_id(91283);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-06-06 18:38:55 +0530 (Mon, 06 Jun 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("ImageMagick Multiple Unspecified Vulnerabilities (Windows)");

  script_tag(name:"summary", value:"The host is installed with ImageMagick
  and is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws are due to,

  - An error in ReadDCMImage function in DCM reader in computing the
    pixel scaling table.

  - The lack of validation of pixel.red, pixel.green and pixel.blue by DCM reader.

  - The lack of NULL pointer checks by DCM reader.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to cause some unspecified impacts.");

  script_tag(name:"affected", value:"ImageMagick versions before 6.9.4-5 and
  7.x before 7.0.1-7 on Windows.");

  script_tag(name:"solution", value:"Upgrade to ImageMagick version
  6.9.4-5 or 7.0.1-7 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://blog.fuzzing-project.org/46-Various-invalid-memory-reads-in-ImageMagick-WPG,-DDS,-DCM.html");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_imagemagick_detect_win.nasl");
  script_mandatory_keys("ImageMagick/Win/Installed");
  script_xref(name:"URL", value:"http://www.imagemagick.org");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!imVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:imVer, test_version:"6.9.4.5"))
{
  fix = "6.9.4-5";
  VULN = TRUE;
}

else if(imVer =~ "7\.")
{
  if(version_is_less(version:imVer, test_version:"7.0.1.7"))
  {
    fix = "7.0.1-7";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:imVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
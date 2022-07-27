###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_imagemagick_convert_tiff_code_exec_vuln_win.nasl 12051 2018-10-24 09:14:54Z asteins $
#
# ImageMagick Convert Tiff Adobe Deflate Code Execution Vulnerability (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.810260");
  script_version("$Revision: 12051 $");
  script_cve_id("CVE-2016-8707");
  script_bugtraq_id(94727);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-12-29 18:21:52 +0530 (Thu, 29 Dec 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("ImageMagick Convert Tiff Adobe Deflate Code Execution Vulnerability (Windows)");

  script_tag(name:"summary", value:"The host is installed with ImageMagick
  and is prone to a code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an out of bounds write
  error exists in the handling of compressed TIFF images in ImageMagicks's
  convert utility.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to execute arbitrary code in context of the application. Failed
  exploits may result in denial-of-service conditions.");

  script_tag(name:"affected", value:"ImageMagick version 7.0.3-0 through 7.0.3-8
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to version 7.0.3-9 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=50998");
  script_xref(name:"URL", value:"https://www.imagemagick.org/script/changelog.php");
  script_xref(name:"URL", value:"http://www.talosintelligence.com/reports/TALOS-2016-0216");
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

if(imVer =~ "^(7\.0\.3)")
{
  if(version_in_range(version:imVer, test_version:"7.0.3.0", test_version2:"7.0.3.8"))
  {
    report = report_fixed_ver(installed_version:imVer, fixed_version:"7.0.3-9");
    security_message(data:report);
    exit(0);
  }
}

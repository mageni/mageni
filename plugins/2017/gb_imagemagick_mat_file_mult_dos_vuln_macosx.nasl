###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_imagemagick_mat_file_mult_dos_vuln_macosx.nasl 11923 2018-10-16 10:38:56Z mmartin $
#
# ImageMagick Mat File Multiple Denial of Service Vulnerabilities (Mac OS X)
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

CPE = "cpe:/a:imagemagick:imagemagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810292");
  script_version("$Revision: 11923 $");
  script_cve_id("CVE-2016-10070", "CVE-2016-10071");
  script_bugtraq_id(95221, 95222);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-16 12:38:56 +0200 (Tue, 16 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-16 15:59:05 +0530 (Mon, 16 Jan 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("ImageMagick Mat File Multiple Denial of Service Vulnerabilities (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with ImageMagick
  and is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple
  out of bound errors in mat file.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to cause a denial-of-service condition.");

  script_tag(name:"affected", value:"ImageMagick versions before 6.9.4-0
  on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to ImageMagick version
  6.9.4-0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2016/q4/758");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/commit/b173a352397877775c51c9a0e9d59eb6ce24c455");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/commit/f3b483e8b054c50149912523b4773687e18afe25");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_imagemagick_detect_macosx.nasl");
  script_mandatory_keys("ImageMagick/MacOSX/Version");
  script_xref(name:"URL", value:"http://www.imagemagick.org");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!imVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:imVer, test_version:"6.9.4.0"))
{
  report = report_fixed_ver(installed_version:imVer, fixed_version:'6.9.4.0');
  security_message(data:report);
  exit(0);
}

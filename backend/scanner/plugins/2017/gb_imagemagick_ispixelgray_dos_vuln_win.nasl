###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_imagemagick_ispixelgray_dos_vuln_win.nasl 14175 2019-03-14 11:27:57Z cfischer $
#
# ImageMagick 'IsPixelGray' Function Denial of Service Vulnerability (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.810556");
  script_version("$Revision: 14175 $");
  script_cve_id("CVE-2016-9773");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 12:27:57 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-02-20 15:05:25 +0530 (Mon, 20 Feb 2017)");
  script_tag(name:"qod_type", value:"registry");
  script_name("ImageMagick 'IsPixelGray' Function Denial of Service Vulnerability (Windows)");

  script_tag(name:"summary", value:"The host is installed with ImageMagick
  and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a heap-based buffer overflow
  error in the 'IsPixelGray' function in MagickCore/pixel-accessor.h script.");

  script_tag(name:"impact", value:"Successful exploitation will allows remote
  attackers to cause a denial of service (out-of-bounds heap read).");

  script_tag(name:"affected", value:"ImageMagick version 7.0.3-8 on Windows.");

  script_tag(name:"solution", value:"Update to version 7.0.3-9 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/12/02/11");
  script_xref(name:"URL", value:"https://blogs.gentoo.org/ago/2016/12/01/imagemagick-heap-based-buffer-overflow-in-ispixelgray-pixel-accessor-h-incomplete-fix-for-cve-2016-9556");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
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

if(imVer == "7.0.3.8")
{
  report = report_fixed_ver(installed_version:imVer, fixed_version:'7.0.3-9');
  security_message(data:report);
  exit(0);
}

exit(99);
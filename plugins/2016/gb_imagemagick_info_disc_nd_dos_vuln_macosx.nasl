###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_imagemagick_info_disc_nd_dos_vuln_macosx.nasl 12455 2018-11-21 09:17:27Z cfischer $
#
# ImageMagick Information Disclosure And Denial Of Service Vulnerabilities (Mac OS X)
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
  script_oid("1.3.6.1.4.1.25623.1.0.810254");
  script_version("$Revision: 12455 $");
  script_cve_id("CVE-2016-5841", "CVE-2016-5842");
  script_bugtraq_id(91394);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-06-06 18:38:55 +0530 (Mon, 06 Jun 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("ImageMagick Information Disclosure And Denial Of Service Vulnerabilities (Mac OS X)");

  script_tag(name:"summary", value:"The host is installed with ImageMagick
  and is prone to information disclosure and denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws are due to,

  - An integer overflow error in 'MagickCore/profile.c' script.

  - An out-of-bounds read error in 'MagickCore/property.c' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to obtain sensitive memory information and cause a denial of
  service (segmentation fault) or possibly execute arbitrary code.");

  script_tag(name:"affected", value:"ImageMagick versions before 7.0.2-1 on
  Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to ImageMagick version
  7.0.2-1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/06/23/1");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/commits/7.0.2-1");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/06/25/3");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/commit/d8ab7f046587f2e9f734b687ba7e6e10147c294b");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18841");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
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

if(version_is_less(version:imVer, test_version:"7.0.2.1"))
{
  report = report_fixed_ver(installed_version:imVer, fixed_version:"7.0.2-1");
  security_message(data:report);
  exit(0);
}
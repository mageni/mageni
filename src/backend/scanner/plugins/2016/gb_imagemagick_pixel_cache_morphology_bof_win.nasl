###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_imagemagick_pixel_cache_morphology_bof_win.nasl 14181 2019-03-14 12:59:41Z cfischer $
#
# ImageMagick 'ContrastStretchImage()' Buffer Overflow Vulnerability (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.810245");
  script_version("$Revision: 14181 $");
  script_cve_id("CVE-2016-6520");
  script_bugtraq_id(92252);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 13:59:41 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-06-06 18:38:55 +0530 (Mon, 06 Jun 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("ImageMagick 'ContrastStretchImage()' Buffer Overflow Vulnerability (Windows)");

  script_tag(name:"summary", value:"The host is installed with ImageMagick
  and is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an out-of-bounds memory
  read error in 'ContrastStretchImage' function in 'MagickCore/enhance.c' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to disclose potentially sensitive information or cause the
  target application to crash.");

  script_tag(name:"affected", value:"ImageMagick versions before 7.0.2-7 on
  Windows.");

  script_tag(name:"solution", value:"Upgrade to ImageMagick version
  7.0.2-7 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/08/02/10");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1036502");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("secpod_imagemagick_detect_win.nasl");
  script_mandatory_keys("ImageMagick/Win/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!imVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:imVer, test_version:"7.0.2.7"))
{
  report = report_fixed_ver(installed_version:imVer, fixed_version:"7.0.2-7");
  security_message(data:report);
  exit(0);
}

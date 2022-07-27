###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_imagemagick_waveletdenoiseimage_fun_dos_vuln_macosx.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# ImageMagick 'WaveletDenoiseImage' Function Denial of Service Vulnerability (Mac OS X)
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
  script_oid("1.3.6.1.4.1.25623.1.0.810538");
  script_version("$Revision: 11863 $");
  script_cve_id("CVE-2016-9298");
  script_bugtraq_id(94310);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-07 17:14:10 +0530 (Tue, 07 Feb 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("ImageMagick 'WaveletDenoiseImage' Function Denial of Service Vulnerability (Mac OS X)");

  script_tag(name:"summary", value:"The host is installed with ImageMagick
  and is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to heap overflow error
  in the 'WaveletDenoiseImage' function in MagickCore/fx.c script.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to cause a denial of service (crash) via a crafted image.");

  script_tag(name:"affected", value:"ImageMagick versions before 6.9.6-4 and
  7.x before 7.0.3-6 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to ImageMagick version
  6.9.6-4 or 7.0.3-6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/11/14/10");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2016-9298");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/commit/3cbfb163cff9e5b8cdeace8312e9bfee810ed02b");
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

if(version_is_less(version:imVer, test_version:"6.9.6.4"))
{
  fix = "6.9.6-4";
  VULN = TRUE;
}

else if(imVer =~ "^7\.")
{
  if(version_is_less(version:imVer, test_version:"7.0.3.6"))
  {
    fix = "7.0.3-6";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:imVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(0);

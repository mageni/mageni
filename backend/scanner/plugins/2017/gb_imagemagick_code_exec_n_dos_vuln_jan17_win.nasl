###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_imagemagick_code_exec_n_dos_vuln_jan17_win.nasl 11982 2018-10-19 08:49:21Z mmartin $
#
# ImageMagick Code Execution And Denial of Service Vulnerabilities (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.810515");
  script_version("$Revision: 11982 $");
  script_cve_id("CVE-2016-7101", "CVE-2016-6823");
  script_bugtraq_id(93181, 93158);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 10:49:21 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-23 18:09:22 +0530 (Mon, 23 Jan 2017)");
  script_tag(name:"qod_type", value:"registry");
  script_name("ImageMagick Code Execution And Denial of Service Vulnerabilities (Windows)");

  script_tag(name:"summary", value:"The host is installed with ImageMagick
  and is prone to code execution and denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - A buffer-overflow vulnerability in SGI coder, which fails to perform adequate
    boundary checks on user-supplied input.

  - An integer overflow in the BMP coder, which fails to adequately bounds-check
    user-supplied data before copying it into an insufficiently sized buffer.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to execute arbitrary code within the context of the application.
  Failed exploit attempts will likely cause a denial-of-service condition.");

  script_tag(name:"affected", value:"ImageMagick versions before 7.0.2-10
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to ImageMagick version
  7.0.2-10 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/commit/4cc6ec8a4197d4c008577127736bf7985d632323");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/09/26/3");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

if(version_is_less(version:imVer, test_version:"7.0.2.10"))
{
  report = report_fixed_ver(installed_version:imVer, fixed_version:'7.0.2-10');
  security_message(data:report);
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_imagemagick_mult_sec_bypass_vuln_win.nasl 14175 2019-03-14 11:27:57Z cfischer $
#
# ImageMagick Multiple Security Bypass Vulnerabilities (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.810278");
  script_version("$Revision: 14175 $");
  script_cve_id("CVE-2016-10060", "CVE-2016-10061", "CVE-2016-10062");
  script_bugtraq_id(95208, 95207, 95209);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 12:27:57 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-01-13 15:10:00 +0530 (Fri, 13 Jan 2017)");
  script_tag(name:"qod_type", value:"registry");
  script_name("ImageMagick Multiple Security Bypass Vulnerabilities (Windows)");

  script_tag(name:"summary", value:"The host is installed with ImageMagick
  and is prone to multiple security bypass vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple
  fwrite issues and some other unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to bypass certain security restrictions to perform unauthorized
  actions. This may aid in further attacks.");

  script_tag(name:"affected", value:"ImageMagick versions before 7.0.1-10
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to ImageMagick version
  7.0.1-10 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2016/q4/758");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/commit/933e96f01a8c889c7bf5ffd30020e86a02a046e7");
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

if(version_is_less(version:imVer, test_version:"7.0.1.10"))
{
  report = report_fixed_ver(installed_version:imVer, fixed_version:'7.0.1-10');
  security_message(data:report);
  exit(0);
}

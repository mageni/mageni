###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_imagemagick_mult_vuln_may16_win.nasl 11922 2018-10-16 10:24:25Z asteins $
#
# ImageMagick Multiple Vulnerabilities May16 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.807568");
  script_version("$Revision: 11922 $");
  script_cve_id("CVE-2016-3714", "CVE-2016-3715", "CVE-2016-3716", "CVE-2016-3717",
                "CVE-2016-3718");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-16 12:24:25 +0200 (Tue, 16 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-05-05 14:06:00 +0530 (Thu, 05 May 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("ImageMagick Multiple Vulnerabilities May16 (Windows)");

  script_tag(name:"summary", value:"The host is installed with ImageMagick
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws are due to,

  - Insufficient filtering for filename passed to delegate's command.

  - An error in ImageMagick's ephemeral pseudoprotocol.

  - An error in ImageMagick's msl pseudo protocol.

  - An error in ImageMagick's label pseudo protocol.

  - An SSRF vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to execute arbitrary code, to delete arbitrary files, to move image
  files to file with any extension in any folder, to get content of the files
  from the server.");

  script_tag(name:"affected", value:"ImageMagick versions before 6.9.3-10
  and 7.x before 7.0.1-1 on Windows.");

  script_tag(name:"solution", value:"Upgrade to ImageMagick version
  6.9.3-10 or 7.0.1-1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.imagemagick.org/discourse-server/viewtopic.php?f=4&t=29588");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/05/03/18");
  script_xref(name:"URL", value:"https://imagetragick.com");
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

if(version_is_less(version:imVer, test_version:"6.9.3.10"))
{
  fix = "6.9.3.10";
  VULN = TRUE;
}

if(version_in_range(version:imVer, test_version:"7.0.0", test_version2:"7.0.1.0"))
{
  fix = "7.0.1.1";
  VULN = TRUE;
}

if(VULN)
{
  report = report_fixed_ver(installed_version:imVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_graphicsmagick_mult_vuln_feb17_win.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# GraphicsMagick Multiple Vulnerabilities-01 Feb17 (Windows)
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

CPE = "cpe:/a:graphicsmagick:graphicsmagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810560");
  script_version("$Revision: 11863 $");
  script_cve_id("CVE-2016-7446", "CVE-2016-7447", "CVE-2016-7448", "CVE-2016-7449");
  script_bugtraq_id(93074);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-21 10:39:33 +0530 (Tue, 21 Feb 2017)");
  script_name("GraphicsMagick Multiple Vulnerabilities-01 Feb17 (Windows)");

  script_tag(name:"summary", value:"This host is installed with GraphicsMagick
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists as,

  - The TIFF reader had a bug pertaining to use of 'TIFFGetField' function when
    a 'count' value is returned.

  - The Utah RLE reader did not validate that header information was
    reasonable given the file size.

  - A heap overflow error in the 'EscapeParenthesis' function.

  - A buffer overflow error in the MVG and SVG rendering code.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a heap read overflow which could allow an untrusted file to
  crash the software, cause huge memory allocations and/or consume huge amounts
  of CPU, cause a denial of service and to have some unspecified impacts.");

  script_tag(name:"affected", value:"GraphicsMagick version before 1.3.25
  on Windows");

  script_tag(name:"solution", value:"Upgrade to GraphicsMagick version 1.3.25
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://blogs.gentoo.org/ago/2016/08/23/graphicsmagick-two-heap-based-buffer-overflow-in-readtiffimage-tiff-c");
  script_xref(name:"URL", value:"https://blogs.gentoo.org/ago/2016/09/07/graphicsmagick-null-pointer-dereference-in-magickstrlcpy-utility-c");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/09/18/8");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2016/q3/550");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_graphicsmagick_detect_win.nasl");
  script_mandatory_keys("GraphicsMagick/Win/Installed");
  script_xref(name:"URL", value:"http://www.graphicsmagick.org");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!gmVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:gmVer, test_version:"1.3.25"))
{
  report = report_fixed_ver(installed_version:gmVer, fixed_version:"1.3.25");
  security_message(data:report);
  exit(0);
}

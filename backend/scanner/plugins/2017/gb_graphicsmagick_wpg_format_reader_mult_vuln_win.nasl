###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_graphicsmagick_wpg_format_reader_mult_vuln_win.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# GraphicsMagick Multiple Vulnerabilities - Feb17 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.810537");
  script_version("$Revision: 11863 $");
  script_cve_id("CVE-2016-7996", "CVE-2016-7997", "CVE-2016-7800");
  script_bugtraq_id(93467, 93464, 96135);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-02 14:58:13 +0530 (Thu, 02 Feb 2017)");
  script_name("GraphicsMagick Multiple Vulnerabilities - Feb17 (Windows)");

  script_tag(name:"summary", value:"This host is installed with GraphicsMagick
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists as,

  - In a build with QuantumDepth=8 (the default), there is no check that the
    provided colormap is not larger than 256 entries, resulting in potential
    heap overflow.

  - A logic error which leads to passing a NULL pointer where a NULL pointer
    is not allowed.

  - An integer underflow error in the parse8BIM function in coders/meta.c
    script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service and to have unspecified impact.");

  script_tag(name:"affected", value:"GraphicsMagick version 1.3.25 and earlier
  on Windows");

  script_tag(name:"solution", value:"Apply the appropriate patch from the vendor.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/10/08/5");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/10/01/7");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2016/q4/55");

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

if(version_is_less_equal(version:gmVer, test_version:"1.3.25"))
{
  report = report_fixed_ver(installed_version:gmVer, fixed_version:"Apply the patch");
  security_message(data:report);
  exit(0);
}

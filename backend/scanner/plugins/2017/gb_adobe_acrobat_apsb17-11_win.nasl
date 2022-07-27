###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_acrobat_apsb17-11_win.nasl 11919 2018-10-16 09:49:19Z mmartin $
#
# Adobe Acrobat Security Updates(apsb17-11)-Windows
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:adobe:acrobat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810872");
  script_version("$Revision: 11919 $");
  script_cve_id("CVE-2017-3011", "CVE-2017-3012", "CVE-2017-3013", "CVE-2017-3014",
                "CVE-2017-3015", "CVE-2017-3018", "CVE-2017-3019", "CVE-2017-3020",
                "CVE-2017-3021", "CVE-2017-3022", "CVE-2017-3024", "CVE-2017-3025",
                "CVE-2017-3026", "CVE-2017-3027", "CVE-2017-3028", "CVE-2017-3030",
                "CVE-2017-3031", "CVE-2017-3032", "CVE-2017-3033", "CVE-2017-3034",
                "CVE-2017-3036", "CVE-2017-3037", "CVE-2017-3038", "CVE-2017-3039",
                "CVE-2017-3040", "CVE-2017-3042", "CVE-2017-3043", "CVE-2017-3044",
                "CVE-2017-3045", "CVE-2017-3046", "CVE-2017-3048", "CVE-2017-3049",
                "CVE-2017-3050", "CVE-2017-3051", "CVE-2017-3052", "CVE-2017-3054",
                "CVE-2017-3055", "CVE-2017-3056", "CVE-2017-3057", "CVE-2017-3065",
                "CVE-2017-3035", "CVE-2017-3047", "CVE-2017-3017", "CVE-2017-3023",
                "CVE-2017-3041", "CVE-2017-3029", "CVE-2017-3053");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-16 11:49:19 +0200 (Tue, 16 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-14 12:38:23 +0530 (Fri, 14 Apr 2017)");
  script_name("Adobe Acrobat Security Updates(apsb17-11)-Windows");

  script_tag(name:"summary", value:"This host is installed with Adobe Acrobat
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - use-after-free vulnerabilities.

  - heap buffer overflow vulnerabilities.

  - memory corruption vulnerabilities.

  - integer overflow vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to conduct code execution attacks.");

  script_tag(name:"affected", value:"Adobe Acrobat version 11.x before
  11.0.20 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Acrobat version
  11.0.20 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb17-11.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Acrobat/Win/Installed");
  script_xref(name:"URL", value:"http://www.adobe.com/in/products/acrobat.html");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!readerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:readerVer, test_version:"11.0", test_version2:"11.0.19"))
{
  report = report_fixed_ver(installed_version:readerVer, fixed_version:"11.0.20");
  security_message(data:report);
  exit(0);
}
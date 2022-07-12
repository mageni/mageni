###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_itunes_mult_vuln_HT207598.nasl 11977 2018-10-19 07:28:56Z mmartin $
#
# Apple iTunes Multiple Vulnerabilities-HT207598 (MACOSX)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810725");
  script_version("$Revision: 11977 $");
  script_cve_id("CVE-2009-3270", "CVE-2009-3560", "CVE-2009-3720", "CVE-2012-1147",
                "CVE-2012-1148", "CVE-2012-6702", "CVE-2013-7443", "CVE-2015-1283",
                "CVE-2015-3414", "CVE-2015-3415", "CVE-2015-3416", "CVE-2015-3717",
                "CVE-2015-6607", "CVE-2016-0718", "CVE-2016-4472", "CVE-2016-5300",
                "CVE-2016-6153");
  script_bugtraq_id(74228);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 09:28:56 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-30 17:45:29 +0530 (Thu, 30 Mar 2017)");
  script_name("Apple iTunes Multiple Vulnerabilities-HT207598 (MACOSX)");

  script_tag(name:"summary", value:"This host is installed with Apple iTunes
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to the multiple
  issues in SQLite and expat");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code, cause unexpected application termination
  and disclose sensitive information.");

  script_tag(name:"affected", value:"Apple iTunes versions before 12.6 on MACOSX");

  script_tag(name:"solution", value:"Upgrade to Apple iTunes 12.6.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT207598");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_itunes_detect_macosx.nasl");
  script_mandatory_keys("Apple/iTunes/MacOSX/Version");
  script_xref(name:"URL", value:"http://www.apple.com/itunes");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!ituneVer = get_app_version(cpe:CPE)){
  exit(0);
}

##  Check for Apple iTunes vulnerable versions
if(version_is_less(version:ituneVer, test_version:"12.6"))
{
  report = report_fixed_ver(installed_version:ituneVer, fixed_version:"12.6");
  security_message(data:report);
  exit(0);
}

#############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trendmicro_imsva_auth_bypass.nasl 14156 2019-03-13 14:38:13Z cfischer $
#
# Trend Micro InterScan Messaging Security (Virtual Appliance) [IMSVA] Management Portal Authentication Bypass Vulnerability
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = 'cpe:/a:trendmicro:interscan_messaging_security_virtual_appliance';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107298");
  script_version("$Revision: 14156 $");
  script_cve_id("CVE-2018-3609");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_tag(name:"last_modification", value:"$Date: 2019-03-13 15:38:13 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-02-14 11:00:01 +0100 (Wed, 14 Feb 2018)");
  script_name("Trend Micro InterScan Messaging Security (Virtual Appliance) [IMSVA] Management Portal Authentication Bypass Vulnerability");

  script_tag(name:"summary", value:"IMSVA management portal is vulnerable to authentication bypass vulnerability");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"This vulnerability could allow an unauthenticated user to access sensitive information in a particular log file that could be used for authentication bypass.");

  script_tag(name:"solution", value:"Update to Version 9.1 Patch 1 CP1682 or Version 9.0 CP1653.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"affected", value:"Versions 9.0 and 9.1");

  script_tag(name:"qod_type", value:"package");


  script_xref(name:"URL", value:"https://success.trendmicro.com/solution/1119277");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_trend_micro_interscan_messaging_security_virtual_appliance_version.nasl");
  script_mandatory_keys("IMSVA/version", "IMSVA/build");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

tmVer = get_app_version(cpe:CPE);
if(!tmVer){
  exit(0);
}

if(!build = get_kb_item("IMSVA/build")){
  exit(0);
}

if((tmVer == "9.1") && (version_is_less(version:build, test_version:"1682")))
{
  report = report_fixed_ver(installed_version:"9.1 build " + build, fixed_version:"9.1 build 1682");
  Vuln = TRUE;
} else if ((tmVer == "9.0") && (version_is_less(version:build, test_version:"1653")))
{
  report = report_fixed_ver(installed_version:"9.0 build " + build, fixed_version:"9.0 build 1653");
  Vuln = TRUE;
}
if (!isnull(Vuln))
{
  security_message(data:report);
  exit(0);
}
exit(99);

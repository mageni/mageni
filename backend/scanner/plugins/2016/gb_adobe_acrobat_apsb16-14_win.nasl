###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_acrobat_apsb16-14_win.nasl 11969 2018-10-18 14:53:42Z asteins $
#
# Adobe Acrobat Security Updates(apsb16-14)-Windows
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:adobe:acrobat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807697");
  script_version("$Revision: 11969 $");
  script_cve_id("CVE-2016-1037", "CVE-2016-1038", "CVE-2016-1039", "CVE-2016-1040",
		"CVE-2016-1041", "CVE-2016-1042", "CVE-2016-1043", "CVE-2016-1044",
		"CVE-2016-1045", "CVE-2016-1046", "CVE-2016-1047", "CVE-2016-1048",
		"CVE-2016-1049", "CVE-2016-1050", "CVE-2016-1051", "CVE-2016-1052",
		"CVE-2016-1053", "CVE-2016-1054", "CVE-2016-1055", "CVE-2016-1056",
		"CVE-2016-1057", "CVE-2016-1058", "CVE-2016-1059", "CVE-2016-1060",
		"CVE-2016-1061", "CVE-2016-1062", "CVE-2016-1063", "CVE-2016-1064",
		"CVE-2016-1065", "CVE-2016-1066", "CVE-2016-1067", "CVE-2016-1068",
		"CVE-2016-1069", "CVE-2016-1070", "CVE-2016-1071", "CVE-2016-1072",
		"CVE-2016-1073", "CVE-2016-1074", "CVE-2016-1075", "CVE-2016-1076",
		"CVE-2016-1077", "CVE-2016-1078", "CVE-2016-1079", "CVE-2016-1080",
		"CVE-2016-1081", "CVE-2016-1082", "CVE-2016-1083", "CVE-2016-1084",
		"CVE-2016-1085", "CVE-2016-1086", "CVE-2016-1087", "CVE-2016-1088",
		"CVE-2016-1090", "CVE-2016-1092", "CVE-2016-1093", "CVE-2016-1094",
		"CVE-2016-1095", "CVE-2016-1112", "CVE-2016-1116", "CVE-2016-1117",
		"CVE-2016-1118", "CVE-2016-1119", "CVE-2016-1120", "CVE-2016-1121",
		"CVE-2016-1122", "CVE-2016-1123", "CVE-2016-1124", "CVE-2016-1125",
		"CVE-2016-1126", "CVE-2016-1127", "CVE-2016-1128", "CVE-2016-1129",
		"CVE-2016-1130", "CVE-2016-4088", "CVE-2016-4089", "CVE-2016-4090",
		"CVE-2016-4091", "CVE-2016-4092", "CVE-2016-4093", "CVE-2016-4094",
		"CVE-2016-4096", "CVE-2016-4097", "CVE-2016-4098", "CVE-2016-4099",
		"CVE-2016-4100", "CVE-2016-4101", "CVE-2016-4102", "CVE-2016-4103",
		"CVE-2016-4104", "CVE-2016-4105", "CVE-2016-4106", "CVE-2016-4107");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 16:53:42 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-05-12 10:27:43 +0530 (Thu, 12 May 2016)");
  script_name("Adobe Acrobat Security Updates(apsb16-14)-Windows");

  script_tag(name:"summary", value:"This host is installed with Adobe Acrobat
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws exist due to,

  - Multiple use-after-free vulnerabilities.

  - Multiple heap buffer overflow vulnerabilities.

  - The memory corruption vulnerabilities.

  - An integer overflow vulnerability.

  - Multiple vulnerabilities in the directory search path used to find resources.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attacker to execute arbitrary code or cause a
  denial of service.");

  script_tag(name:"affected", value:"Adobe Acrobat version 11.x before 11.0.16 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Acrobat version
  11.0.16 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb16-14.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

if(version_in_range(version:readerVer, test_version:"11.0", test_version2:"11.0.15"))
{
  report = report_fixed_ver(installed_version:readerVer, fixed_version:"11.0.16");
  security_message(data:report);
  exit(0);
}

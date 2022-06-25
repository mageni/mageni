###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_microsoft_skype_dll_hijacking_vuln.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# Microsoft Skype DLL Hijacking Vulnerability
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

CPE = "cpe:/a:skype:skype";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809881");
  script_version("$Revision: 11874 $");
  script_cve_id("CVE-2016-5720");
  script_bugtraq_id(95859);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-03 13:26:18 +0530 (Fri, 03 Feb 2017)");
  script_name("Microsoft Skype DLL Hijacking Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Microsoft Skype
  and is prone to DLL hijacking vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to Skype looks for a
  specific DLL by dynamically going through a set of predefined directories. One
  of the directory being scanned is the installation directory, and this is exactly
  what is abused in this vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to execute arbitrary code and conduct DLL hijacking
  attacks via a Trojan horse.");

  script_tag(name:"affected", value:"Microsoft Skype prior to 7.30.80.103
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Microsoft skype Version
  7.30.80.103 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Sep/65");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_skype_detect_win.nasl");
  script_mandatory_keys("Skype/Win/Ver");
  script_xref(name:"URL", value:"https://www.skype.com/en");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
   exit(0);
}

# Skype 7.30.80.103 the exploit is not working
if(version_is_less(version:ffVer, test_version:"7.30.80.103"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"7.30.80.103");
  security_message(data:report);
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_security_scan_plus_priv_esca_vuln.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# McAfee Security Scan Plus Privilege Escalation Vulnerability (Windows)
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

CPE = "cpe:/a:intel:mcafee_security_scan_plus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810824");
  script_version("$Revision: 11874 $");
  script_cve_id("CVE-2016-8008");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-22 11:37:02 +0530 (Wed, 22 Mar 2017)");
  script_name("McAfee Security Scan Plus Privilege Escalation Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with McAfee Security
  Scan Plus and is prone to privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to McUICnt.exe, an
  executable file used in McAfee Security Scan Plus, used to load Version.DLL
  from the current user directory.");

  script_tag(name:"impact", value:"Successful exploitation will lead to loading
  of a replacement DLL onto a Windows machine.");

  script_tag(name:"affected", value:"McAfee Security Scan Plus version
  prior to 3.11.427.2");

  script_tag(name:"solution", value:"Upgrade to McAfee Security scan plus
  3.11.427.2.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://service.mcafee.com/webcenter/portal/cp/home/articleview?articleId=TS102593");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mcafee_security_scan_plus_detect.nasl");
  script_mandatory_keys("McAfee/SecurityScanPlus/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("secpod_reg.inc");
include("version_func.inc");

if(hotfix_check_sp(win7:2, win7x64:2, win10:1, win10x64:1) <= 0){
  exit(0);
}

if(!msspVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:msspVer, test_version:"3.11.427.2"))
{
  report = report_fixed_ver(installed_version:msspVer, fixed_version:"3.11.427.2");
  security_message(data:report);
  exit(0);
}

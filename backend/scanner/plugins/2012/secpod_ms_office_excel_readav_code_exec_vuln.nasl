###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_office_excel_readav_code_exec_vuln.nasl 11374 2018-09-13 12:45:05Z asteins $
#
# Microsoft Office Excel ReadAV Arbitrary Code Execution Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902692");
  script_version("$Revision: 11374 $");
  script_cve_id("CVE-2012-5672");
  script_bugtraq_id(56309);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-13 14:45:05 +0200 (Thu, 13 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-11-08 14:28:19 +0530 (Thu, 08 Nov 2012)");
  script_name("Microsoft Office Excel ReadAV Arbitrary Code Execution Vulnerability");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2012/Oct/63");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/524379");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Prdts/Installed");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
code or or cause denial of service condition via a crafted XLS file.");
  script_tag(name:"affected", value:"Microsoft Excel Viewer 2007 Service Pack 3 and prior
Microsoft Office 2007 Service Pack 2 and Service Pack 3");
  script_tag(name:"insight", value:"An error exists in the Microsoft Office Excel Viewer and Excel
when handling crafted '.xls' files.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with Microsoft Office Excel which is
prone to arbitrary code execution vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");

excelVer = get_kb_item("SMB/Office/Excel/Version");
if(excelVer =~ "^12")
{
  if(version_in_range(version:excelVer, test_version:"12.0", test_version2:"12.0.6665.5003"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

# Microsoft Office Excel Viewer 2007
excelviewVer = get_kb_item("SMB/Office/XLView/Version");
if(excelviewVer =~ "^12")
{
  if(version_in_range(version:excelviewVer, test_version:"12.0", test_version2:"12.0.6665.5003"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

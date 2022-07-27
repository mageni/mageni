##############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Exchange Server Multiple Vulnerabilities (3009712)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:microsoft:exchange_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805115");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2014-6319", "CVE-2014-6325", "CVE-2014-6326", "CVE-2014-6336");
  script_bugtraq_id(71437, 71440, 71441, 71443);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2014-12-10 15:28:46 +0530 (Wed, 10 Dec 2014)");
  script_name("Microsoft Exchange Server Multiple Vulnerabilities (3009712)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS14-075.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An error when validating a request token.

  - Certain unspecified input is not properly sanitised before being returned
    to the user.

  - Certain input related to redirection tokens is not properly verified before
    being used to redirect users.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct spoofing and cross-site scripting attacks.");

  script_tag(name:"affected", value:"Microsoft Exchange Server 2007 Service Pack 3 and prior

  Microsoft Exchange Server 2010 Service Pack 3 and prior

  Microsoft Exchange Server 2013 Service Pack 1 and prior

  Microsoft Exchange Server 2013 Cumulative Update 6.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/61155");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2996150");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2986475");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/3011140");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS14-075");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_exchange_server_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Exchange/Server/Ver");
  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

exchangePath = get_app_location(cpe:CPE);
if(!exchangePath || "Could not find the install location" >< exchangePath){
  exit(0);
}

exeVer = fetch_file_version(sysPath:exchangePath, file_name:"Bin\ExSetup.exe");
if(exeVer)
{
  if(version_in_range(version:exeVer, test_version:"8.0", test_version2:"8.3.389.1") ||
     version_in_range(version:exeVer, test_version:"14.0", test_version2:"14.3.224.0") ||
     version_in_range(version:exeVer, test_version:"15.0", test_version2:"15.0.847.34"))

  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }

  if(get_kb_item("MS/Exchange/Cumulative/Update"))
  {
    if(version_in_range(version:exeVer, test_version:"15.0", test_version2:"15.0.995.33"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

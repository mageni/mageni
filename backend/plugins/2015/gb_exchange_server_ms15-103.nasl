###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Exchange Server information Disclosure Vulnerability (3089250)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806108");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2015-2505", "CVE-2015-2543", "CVE-2015-2544");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2015-09-09 09:39:00 +0530 (Wed, 09 Sep 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Exchange Server information Disclosure Vulnerability (3089250)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-103.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to Microsoft Exchange web
  applications when Exchange does not properly manage same-origin policy.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to scan and attack systems behind a firewall that are normally
  inaccessible from the outside world, enumerate and attack services that are
  running on these host systems and exploit host-based authentication services.");

  script_tag(name:"affected", value:"Microsoft Exchange Server 2013 SP1,

  Microsoft Exchange Server 2013 Cumulative Update 9 and

  Microsoft Exchange Server 2013 Cumulative Update 8");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3089250");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-103");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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
if(!exeVer){
  exit(0);
}

if (exeVer =~ "^(15\.0\.8)"){
  if(version_in_range(version:exeVer, test_version:"15.0.800.00", test_version2:"15.0.847.42"))
  {
    report = 'File checked:     ' + exchangePath + "Bin\ExSetup.exe" + '\n' +
             'File version:     ' + exeVer  + '\n' +
             'Vulnerable range:  15.0.800.00 - 15.0.847.42' + '\n' ;
    security_message(data:report);
    exit(0);
  }
}

else if(exeVer =~ "^(15\.0\.10)"){
  if(version_in_range(version:exeVer, test_version:"15.0.1000.00", test_version2:"15.0.1076.13"))
  {
    report = 'File checked:     ' + exchangePath + "Bin\ExSetup.exe" + '\n' +
             'File version:     ' + exeVer  + '\n' +
             'Vulnerable range:  15.0.1000.00 - 15.0.1076.13' + '\n' ;
    security_message(data:report);
    exit(0);
  }
}

else if (exeVer =~ "^(15\.0\.11)"){
  if(version_in_range(version:exeVer, test_version:"15.0.1100.00", test_version2:"15.0.1104.7"))
  {
    report = 'File checked:     ' + exchangePath + "Bin\ExSetup.exe" + '\n' +
             'File version:     ' + exeVer  + '\n' +
             'Vulnerable range:  15.0.1100.00 - 15.0.1104.7' + '\n' ;
    security_message(data:report);
    exit(0);
  }
}

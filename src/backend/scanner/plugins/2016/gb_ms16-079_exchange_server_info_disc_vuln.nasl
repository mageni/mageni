###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Exchange Server Information Disclosure Vulnerability (3160339)
#
# Authors:
# Rinu Kuriakose <bshakeel@secpod.com>
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
CPE = "cpe:/a:microsoft:exchange_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809010");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2016-0028");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-08-24 17:40:12 +0530 (Wed, 24 Aug 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Microsoft Exchange Server Information Disclosure Vulnerability (3160339)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-079.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in email filter
  bypass in the way that Microsoft Exchange parses HTML messages.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to track users via a crafted HTML e-mail message. An attacker could
  also combine this vulnerability with another one, such as a
  Cross-Site Request Forgery (CSRF), to amplify the attack.");

  script_tag(name:"affected", value:"Microsoft Exchange Server 2013 Service Pack 1

  Microsoft Exchange Server 2013 Cumulative Update 11

  Microsoft Exchange Server 2013 Cumulative Update 12

  Microsoft Exchange Server 2016

  Microsoft Exchange Server 2016 Cumulative Update 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3160339");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-079");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

cum_update = get_kb_item("MS/Exchange/Cumulative/Update/no");

exeVer = fetch_file_version(sysPath:exchangePath, file_name:"Bin\ExSetup.exe");
if(exeVer)
{
  ##https://support.microsoft.com/en-us/kb/3150501
  ## Exchange Server 2013
  if(version_in_range(version:exeVer, test_version:"15.0", test_version2:"15.0.847.46"))
  {
    Vulnerable_range = "15.0 - 15.0.847.46";
    VULN = TRUE ;
  }

  ## Exchange Server 2013 CU 11
  if(exeVer =~ "^(15.0)" && "Cumulative Update 11" >< cum_update)
  {
    if(version_is_less(version:exeVer, test_version:"15.0.1156.10"))
    {
      Vulnerable_range = "Less than 15.0.1156.10";
      VULN = TRUE ;
    }
  }

  ## Exchange Server 2013 CU 12
  if(exeVer =~ "^(15.0)" && "Cumulative Update 12" >< cum_update)
  {
    if(version_is_less(version:exeVer, test_version:"15.0.1178.6"))
    {
      Vulnerable_range = "Less than 15.0.1178.6";
      VULN = TRUE ;
    }
  }

  ## Exchange Server 2016
  else if(version_in_range(version:exeVer, test_version:"15.1",  test_version2:"15.1.225.48"))
  {
    Vulnerable_range = "15.1 - 15.1.225.48";
    VULN = TRUE ;
  }

  ##Exchange Server 2016 CU 1
  if(exeVer =~ "^(15.1)" && "Cumulative Update 1" >< cum_update)
  {
    if(version_is_less(version:exeVer, test_version:"15.1.396.33"))
    {
      Vulnerable_range = "Less than 15.1.396.33";
      VULN = TRUE ;
    }
  }

}

if(VULN)
{
  report = 'File checked:     ' + exchangePath + "\Bin\ExSetup.exe" + '\n' +
           'File version:     ' + exeVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}

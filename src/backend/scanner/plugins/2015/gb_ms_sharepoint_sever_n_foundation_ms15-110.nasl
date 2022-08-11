###############################################################################
# OpenVAS Vulnerability Test
#
# MS SharePoint Server and Foundation Multiple Vulnerabilities (3096440)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:microsoft:sharepoint_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805993");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2015-2556", "CVE-2015-6039", "CVE-2015-6037");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2015-10-14 11:40:02 +0530 (Wed, 14 Oct 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("MS SharePoint Server and Foundation Multiple Vulnerabilities (3096440)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-110.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An error in the SharePoint InfoPath Forms Services improperly parses the
  Document Type Definition (DTD) of an XML file.

  - An error as SharePoint does not enforce the appropriate permission level
  for an application or user.

  - An error when an Office Web Apps Server does not properly sanitize a specially
  crafted request.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to perform cross-site scripting attacks on affected systems, bypass
  security restrictions and gain access to sensitive information.");

  script_tag(name:"affected", value:"Microsoft SharePoint Server 2007 Service Pack 3

  Microsoft SharePoint Server 2010 Service Pack 2

  Microsoft SharePoint Server 2013 Service Pack 1 and

  Microsoft SharePoint Foundation 2013 Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3085567");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3085582");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/ms15-110.aspx");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/2553405");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/2596670");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_sharepoint_sever_n_foundation_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/SharePoint/Server_or_Foundation_or_Services/Installed");
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE ) )
  if( ! infos = get_app_version_and_location( cpe:'cpe:/a:microsoft:sharepoint_foundation', exit_no_version:TRUE ) ) exit( 0 );

shareVer = infos['version'];
path = infos['location'];
if(!path || "Could not find the install location" >< path){
  exit(0);
}

## SharePoint Server 2013
if(shareVer =~ "^15\..*")
{
  path = path + "15.0\Bin";

  dllVer = fetch_file_version(sysPath:path, file_name:"Microsoft.office.server.conversions.launcher.exe");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"15.0", test_version2:"15.0.4569.999"))
    {
      report = 'File checked:     ' +  path + "Microsoft.office.server.conversions.launcher.exe" + '\n' +
               'File version:     ' +  dllVer  + '\n' +
               'Vulnerable range: ' + "15.0 - 15.0.4569.999" + '\n' ;

      security_message(data:report);
    }
  }
}

## Foundation 2013
if(shareVer =~ "^15\..*")
{
  path1 = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                         item:"CommonFilesDir");
  if(path1)
  {
    path1 = path1 + "\microsoft shared\SERVER15\Server Setup Controller";

    dllVer = fetch_file_version(sysPath:path, file_name:"Wsssetup.dll");
    if(dllVer)
    {
      if(version_in_range(version:dllVer, test_version:"15.0", test_version2:"15.0.4763.999"))
      {
        report = 'File checked:     ' +  path1 + "Wsssetup.dll" + '\n' +
                 'File version:     ' + dllVer  + '\n' +
                 'Vulnerable range: 15.0.4763.999' + '\n' ;
        security_message(data:report);
        exit(0);
      }
    }
  }
}

#### SharePoint Server 2010
if(shareVer =~ "^14\..*")
{
  path = path + "14.0\Bin";

  ##
  dllVer = fetch_file_version(sysPath:path, file_name:"microsoft.office.infopath.server.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.7159.4999"))
    {
      report = 'File checked:     ' +  path + "microsoft.office.infopath.server.dll" + '\n' +
               'File version:     ' +  dllVer  + '\n' +
               'Vulnerable range: ' + "14 - 14.0.7159.4999" + '\n' ;

      security_message(data:report);
      exit(0);
    }
  }
}

#### SharePoint Server 2007
if(shareVer =~ "^12\..*")
{
  path = path + "12.0\Bin";

  dllVer = fetch_file_version(sysPath:path, file_name:"microsoft.office.infopath.server.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"12.0", test_version2:"12.0.6732.4999"))
    {
      report = 'File checked:     ' +  path + "microsoft.office.infopath.server.dll" + '\n' +
               'File version:     ' +  dllVer  + '\n' +
               'Vulnerable range: ' + "14 - 14.0.7159.4999" + '\n' ;

      security_message(data:report);
      exit(0);
    }
  }
}

exit(99);
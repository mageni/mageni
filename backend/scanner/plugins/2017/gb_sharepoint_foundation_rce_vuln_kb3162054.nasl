##############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft SharePoint Foundation RCE Vulnerability (KB3162054)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:microsoft:sharepoint_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811040");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2017-0281");
  script_bugtraq_id(98297);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-05-11 15:55:30 +0530 (Thu, 11 May 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft SharePoint Foundation RCE Vulnerability (KB3162054)");

  script_tag(name:"summary", value:"This host is missing an important security
  update for Microsoft SharePoint Foundation according to Microsoft KB3162054");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error when the Office
  software fails to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user on an
  affected system.");

  script_tag(name:"affected", value:"Microsoft SharePoint Foundation 2013 Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3162054");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_sharepoint_sever_n_foundation_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/SharePoint/Server/Ver");
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
shareVer = infos['version'];
path = infos['location'];
if(!path || "Could not find the install location" >< path){
  exit(0);
}

##Microsoft SharePoint Foundation 2013
if(shareVer =~ "^15\.")
{
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Office15.WSS",
                         item:"InstallLocation");
  if(path)
  {
    ##msoserver.dll path
    path = path + "\15.0\WebServices\ConversionServices";

    dllVer = fetch_file_version(sysPath:path, file_name:"msoserver.dll");
    if(dllVer && version_in_range(version:dllVer, test_version:"15.0", test_version2:"15.0.4927.0999"))
    {
      report = 'File checked:     ' +  path + "\Onetutil.dll"+ '\n' +
               'File version:     ' +  dllVer  + '\n' +
               'Vulnerable range: ' +  "15.0 - 15.0.4927.0999" + '\n' ;
      security_message(data:report);
      exit(0);
    }
  }
}

exit(99);

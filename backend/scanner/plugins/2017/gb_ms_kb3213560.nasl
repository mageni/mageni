###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft SharePoint Server 2013 Service Pack 1 Remote Code Execution Vulnerability (KB3213560)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811669");
  script_version("2019-05-20T11:12:48+0000");
  script_cve_id("CVE-2017-8742");
  script_bugtraq_id(100741);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-20 11:12:48 +0000 (Mon, 20 May 2019)");
  script_tag(name:"creation_date", value:"2017-09-13 09:21:36 +0530 (Wed, 13 Sep 2017)");
  script_name("Microsoft SharePoint Server 2013 Service Pack 1 Remote Code Execution Vulnerability (KB3213560)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB3213560");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to Microsoft Office software
  fails to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code in the context of the current user.");

  script_tag(name:"affected", value:"Microsoft SharePoint Server 2013 Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3213560");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_sharepoint_sever_n_foundation_detect.nasl");
  script_mandatory_keys("MS/SharePoint/Server/Ver");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if( ! infos = get_app_version_and_location( cpe:"cpe:/a:microsoft:sharepoint_server", exit_no_version:TRUE ) ) exit( 0 );

shareVer = infos['version'];
if(!shareVer || shareVer !~ "^15\."){
  exit(0);
}

path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Office15.OSERVER",
                         item:"InstallLocation");
if(path)
{
  path = path + "\15.0\WebServices\ConversionServices";

  dllVer = fetch_file_version(sysPath:path, file_name:"microsoft.office.server.native.dll");
  if(dllVer && dllVer =~ "^15\.")
  {
    if(version_is_less(version:dllVer, test_version:"15.0.4919.1000"))
    {
      report = 'File checked:     ' +  path + "\microsoft.office.server.native.dll"+ '\n' +
               'File version:     ' +  dllVer  + '\n' +
               'Vulnerable range: ' +  "15.0 - 15.0.4919.0999" + '\n' ;
      security_message(data:report);
      exit(0);
    }
  }
}

exit(99);

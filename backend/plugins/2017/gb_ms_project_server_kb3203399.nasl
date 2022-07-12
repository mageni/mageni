###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Project Server 2013 XSS Vulnerability (KB3203399)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:microsoft:project_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810948");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2017-8551");
  script_bugtraq_id(98913);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-06-16 11:00:41 +0530 (Fri, 16 Jun 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Project Server 2013 XSS Vulnerability (KB3203399)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB3203399");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when SharePoint Server does
  not properly sanitize a specially crafted web request to an affected
  SharePoint server.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker who successfully exploited the vulnerability to perform
  cross-site scripting attacks on affected systems and run script in the
  security context of the current user.");

  script_tag(name:"affected", value:"Microsoft Project Server 2013 Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3203399");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_project_server_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/ProjectServer/Server/Ver");

  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

psVer = get_app_version(cpe:CPE);
if(!psVer){
  exit(0);
}

## Microsoft Project Server 2013
if(psVer =~ "^15\..*")
{
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                         item:"CommonFilesDir");
  if(path)
  {
    path = path + "\Microsoft Shared\web server extensions\15\CONFIG\BIN";

    dllVer = fetch_file_version(sysPath:path,
             file_name:"microsoft.office.project.server.pwa.applicationpages.dll");

    if(dllVer && dllVer =~ "^15\.")
    {
      if(version_is_less(version:dllVer, test_version:"15.0.4919.1000"))
      {
        report = 'File checked:     ' + path + "\Microsoft.office.project.server.pwa.applicationpages.dll" + '\n' +
                 'File version:     ' + dllVer  + '\n' +
                 'Vulnerable range: ' + "15.0 - 15.0.4919.999" + '\n' ;
        security_message(data:report);
        exit(0);
      }
    }
  }
}

###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Web Apps XSS Spoofing Vulnerability (3096440)
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

CPE = "cpe:/a:microsoft:office_web_apps";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805992");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2015-6037");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2015-10-14 10:47:07 +0530 (Wed, 14 Oct 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Web Apps XSS Spoofing Vulnerability (3096440)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS15-110.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw exists as the application fails to
  properly sanitize the malicious crafted request.");

  script_tag(name:"impact", value:"Successful exploitation will allow a
  context-dependent attacker to perform cross-site scripting attacks on
  affected systems and run script in the security context of the current user.");

  script_tag(name:"affected", value:"Microsoft Office Web Apps 2010 Service Pack 2 and prior,

  Microsoft Office Web Apps Server 2013 Service Pack 1 and prior.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3085571");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3085520");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/ms15-110.aspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_office_web_apps_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Office/Web/Apps/Ver");
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
webappVer = infos['version'];
path = infos['location'];
if(!path || "Could not find the install location" >< path){
  exit(0);
}

if(webappVer =~ "^14\..*")
{
  ## Microsoft Word Web Apps 2010
  dllVer = fetch_file_version(sysPath:path,
           file_name:"\14.0\WebServices\ConversionService\Bin\Converter\sword.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.7160.4999"))
    {
     report = 'File checked:     ' +  path + "14.0\WebServices\ConversionService\Bin\Converter\sword.dll" + '\n' +
              'File version:     ' + dllVer  + '\n' +
              'Vulnerable range: ' + "14.0 - 14.0.7160.4999" + '\n' ;

      security_message(data:report);
      exit(0);
    }
  }
}

## Microsoft Office Web Apps 2013
if(webappVer =~ "^15\..*")
{
  path = path + "\PPTConversionService\bin\Converter\";

  dllVer = fetch_file_version(sysPath:path, file_name:"msoserver.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"15.0", test_version2:"15.0.4763.999"))
    {
      report = 'File checked:     ' +  path + "msoserver.dll" + '\n' +
              'File version:     ' +  dllVer  + '\n' +
              'Vulnerable range: ' +  "15.0 - 15.0.4763.999" + '\n' ;

      security_message(data:report);
      exit(0);
    }
  }
}

exit(99);
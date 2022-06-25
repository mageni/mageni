###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft SharePoint Privilege Elevation Vulnerabilities (2663841)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902919");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2012-0017", "CVE-2012-0144", "CVE-2012-0145");
  script_bugtraq_id(51928, 51934, 51937);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2012-06-28 15:51:26 +0530 (Thu, 28 Jun 2012)");
  script_name("Microsoft SharePoint Privilege Elevation Vulnerabilities (2663841)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48029/");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2553413");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2597124");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-011");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected
  site.");
  script_tag(name:"affected", value:"Microsoft SharePoint Server 2010 Service Pack 1 and prior
  Microsoft SharePoint Foundation 2010 Service Pack 1 and prior");
  script_tag(name:"insight", value:"Input passed to 'inplview.aspx', 'themeweb.aspx' and 'skey' parameter in
  'wizardlist.aspx' is not properly sanitised before being returned to the
  user. This can be exploited to execute arbitrary HTML and script code in a
  user's browser session in context of an affected site.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS12-011.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  spName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Microsoft SharePoint Foundation 2010" >< spName ||
     "Microsoft SharePoint Server 2010" >< spName)
  {
    path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                       item:"CommonFilesDir");
    if(path)
    {
      ## For Microsoft SharePoint Foundation 2010
      dllVer = fetch_file_version(sysPath:path,
              file_name:"Microsoft Shared\Web Server Extensions\14\Bin\ONFDA.dll");
      if(dllVer)
      {
        if(version_is_less(version:dllVer, test_version:"14.0.6106.5000"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }
    }

    ## Microsoft SharePoint Server 2010
    spPath = registry_get_sz(key:key + item, item:"InstallLocation");
    if(!spPath){
      exit(0);
    }

    spVer = fetch_file_version(sysPath:spPath, file_name:"14.0\Bin\Microsoft.office.server.native.dll");
    if(!spVer){
      exit(0);
    }

    if(version_is_less(version:spVer, test_version:"14.0.6108.5000"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows ASP.NET Denial of Service Vulnerability(970957)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801482");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2010-12-13 14:33:55 +0100 (Mon, 13 Dec 2010)");
  script_cve_id("CVE-2009-1536");
  script_bugtraq_id(35985);
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_name("Microsoft Windows ASP.NET Denial of Service Vulnerability(970957)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36127/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2231");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/MS09-036");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause the application
  pool on the affected web server to become unresponsive, denying service to
  legitimate users.");
  script_tag(name:"affected", value:"Microsoft .NET Framework 3.5/SP 1
  Microsoft .NET Framework 2.0 SP 1/SP 2");
  script_tag(name:"insight", value:"The flaws is caused by caused by an error in ASP.NET when managing request
  scheduling, which could allow attackers to create specially crafted anonymous
  HTTP requests and cause the web server with ASP.NET in integrated mode to
  become non-responsive.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-036.");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(winVista:3, win2008:3) <= 0){
  exit(0);
}

if((hotfix_missing(name:"972591") == 0) || (hotfix_missing(name:"972592") == 0)||
   (hotfix_missing(name:"972593") == 0) || (hotfix_missing(name:"972594") == 0)){
    exit(0);
}

key = "SOFTWARE\Microsoft\ASP.NET\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  path = registry_get_sz(key:key + item, item:"Path");
  if("\Microsoft.NET\Framework" >< path)
  {
    Ver = fetch_file_version(sysPath:path, file_name:"system.web.dll");
    if(Ver)
    {
      if(hotfix_check_sp(winVista:3, win2008:3) > 0)
      {
        if(version_in_range(version:Ver, test_version:"2.0.50727.1000", test_version2:"2.0.50727.1870") ||
           version_in_range(version:Ver, test_version:"2.0.50727.3000", test_version2:"2.0.50727.3600"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }
    }
  }
}

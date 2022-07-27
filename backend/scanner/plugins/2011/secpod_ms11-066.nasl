###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft .NET Framework Chart Control Information Disclosure Vulnerability (2567943)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902552");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2011-08-11 06:41:03 +0200 (Thu, 11 Aug 2011)");
  script_cve_id("CVE-2011-1977");
  script_bugtraq_id(48985);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("Microsoft .NET Framework Chart Control Information Disclosure Vulnerability (2567943)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45508/");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2487367");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2500170");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms11-066.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow attacker to gain access to sensitive
  information that may aid in further attacks.");
  script_tag(name:"affected", value:"Microsoft .NET Framework 4.0
  Microsoft Chart Control for .NET Framework 3.5 SP1");
  script_tag(name:"insight", value:"The flaw is due to an error in the ASP.NET Chart controls when
  encountering special characters within a URI. This can be exploited to read
  the contents of arbitrary files in the web site directory or subdirectories
  via a specially crafted GET request to a server hosting the Chart controls.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS11-066.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:2) <= 0){
  exit(0);
}

## MS11-066 Hotfix
if((hotfix_missing(name:"2487367") == 0) ||
   (hotfix_missing(name:"2500170") == 0)) {
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
    dllVer = fetch_file_version(sysPath:path,
                                file_name:"System.Web.DataVisualization.dll");
    if(dllVer)
    {
      ## .NET Framework 4.0 GDR 4.0.30319.236 LDR 4.0.30319.461
      if(version_in_range(version:dllVer, test_version:"4.0.30319.000", test_version2:"4.0.30319.235")||
         version_in_range(version:dllVer, test_version:"4.0.30319.400", test_version2:"4.0.30319.460"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}

key = "SOFTWARE\Microsoft\NET Framework Chart Setup\NDP\v3.5";
if(!registry_key_exists(key:key)){
  exit(0);
}

chartPath = registry_get_sz(key:key, item:"InstallPath");
if(! chartPath){
  exit(0);
}

chartVer = fetch_file_version(sysPath:chartPath, file_name:"System.Web.DataVisualization.dll");
if(! chartVer){
  exit(0);
}

if(version_in_range(version:chartVer, test_version:"3.5.30729.0000", test_version2:"3.5.30729.5680")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

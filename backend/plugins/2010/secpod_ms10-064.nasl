###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Outlook  TNEF Remote Code Execution Vulnerability (2315011)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902243");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2010-09-15 17:01:07 +0200 (Wed, 15 Sep 2010)");
  script_cve_id("CVE-2010-2728");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Outlook TNEF Remote Code Execution Vulnerability (2315011)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2293422");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2293428");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2288953");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2385");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver", "SMB/Office/Outlook/Version");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code by sending a specially crafted email attachment to an affected system.");
  script_tag(name:"affected", value:"Microsoft Office Outlook 2002/2003/2007");
  script_tag(name:"insight", value:"The flaw is caused by a heap overflow error when processing malformed 'TNEF'
  messages while connected to an Exchange Server in Online Mode, which could
  allow attackers to execute arbitrary code by sending a specially crafted
  email to a vulnerable client.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-064.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms10-064.mspx");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");
include("http_func.inc");

outVer = get_kb_item("SMB/Office/Outlook/Version");
if(!outVer){
  exit(0);
}

key  = "SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDlls\";

foreach dllPath (registry_enum_values(key:key))
{
  if("CONTAB32.DLL" >< dllPath)
  {
    share = ereg_replace(pattern:"([a-zA-Z]):.*", replace:"\1$", string:dllPath);
    file = ereg_replace(pattern:"[a-zA-Z]:(.*)", replace:"\1", string:dllPath);

    dllVer = GetVer(file:file, share:toupper(share));

    if(!isnull(dllVer))
    {
      if(version_is_less(version:dllVer, test_version:"9.0.0.8987")||
         version_in_range(version:dllVer, test_version:"11.0",test_version2:"11.0.8306")||
         version_in_range(version:dllVer, test_version:"12.0",test_version2:"12.0.6514.4999"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
     }
  }
}

###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows DNS Server Denial of Service Vulnerability (2647170)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902906");
  script_version("2019-05-03T12:31:27+0000");
  script_bugtraq_id(52374);
  script_cve_id("CVE-2012-0006");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2012-03-14 08:31:02 +0530 (Wed, 14 Mar 2012)");
  script_name("Microsoft Windows DNS Server Denial of Service Vulnerability (2647170)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attacker to execute arbitrary
  code or to cause the DNS server to stop responding or to restart.");

  script_tag(name:"affected", value:"Microsoft Windows 2K3 Service Pack 2 and prior.

  Microsoft Windows Server 2008 Service Pack 2 and prior.");

  script_tag(name:"insight", value:"The flaws are exists when Windows DNS server processing certain lookup
  queries and can be exploited to restart the DNS server.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS12-017.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/48394");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2647170");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-017");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2003:3, win2008:3) <= 0){
  exit(0);
}

if(!registry_key_exists(key:"SYSTEM\CurrentControlSet\Services\DNS")){
  exit(0);
}

## MS12-017 Hotfix 2647170
if((hotfix_missing(name:"2647170") == 0)){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

sysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Dns.exe");
if(!sysVer){
  exit(0);
}

if(hotfix_check_sp(win2003:3) > 0)
{
  if(version_is_less(version:sysVer, test_version:"5.2.3790.4957")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

if(hotfix_check_sp(win2008:3) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.0.6002.18557")||
     version_in_range(version:sysVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22762")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

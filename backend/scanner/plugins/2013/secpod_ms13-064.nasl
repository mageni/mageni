###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-064.nasl 31155 2013-08-14 14:18:13Z aug$
#
# Microsoft Windows NAT Driver Denial of Service Vulnerability (2849568)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902989");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2013-3182");
  script_bugtraq_id(61685);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2013-08-14 08:17:31 +0530 (Wed, 14 Aug 2013)");
  script_name("Microsoft Windows NAT Driver Denial of Service Vulnerability (2849568)");

  script_tag(name:"summary", value:"This host is missing a important security update according to
Microsoft Bulletin MS13-064.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"insight", value:"The flaw is due to an error within the Windows NAT Driver when handling ICMP
packets.");
  script_tag(name:"affected", value:"Microsoft Windows Server 2012");
  script_tag(name:"impact", value:"Successful exploitation will allow the remote attackers to cause a denial of service.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54420");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2849568");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-064");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2012:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

WinnatVer = fetch_file_version(sysPath:sysPath, file_name:"system32\drivers\Winnat.sys");
if(!WinnatVer){
  exit(0);
}

if(hotfix_check_sp(win2012:1) > 0)
{
  if(version_is_less(version:WinnatVer, test_version:"6.2.9200.16654") ||
     version_in_range(version:WinnatVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.20761")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

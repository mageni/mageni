##############################################################################
# OpenVAS Vulnerability Test
# Description: Microsoft Office Information Disclosure Vulnerability (957699)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900047");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2008-10-15 19:56:48 +0200 (Wed, 15 Oct 2008)");
  script_bugtraq_id(31693);
  script_cve_id("CVE-2008-4020");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_name("Microsoft Office nformation Disclosure Vulnerability (957699)");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms08-056.mspx");
  script_dependencies("secpod_ms_office_detection_900025.nasl");
  script_mandatory_keys("MS/Office/Ver");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation could allow documents incorrectly rendered
  in the web browser, leading to cross site scripting attack.");
  script_tag(name:"affected", value:"Microsoft Office XP Service Pack 3 on Windows (All).");
  script_tag(name:"insight", value:"The flaw exists due to the way that Office processes documents using the CDO
  Protocol (cdo:) and the Content-Disposition Attachment header.");
  script_tag(name:"summary", value:"This host is missing critical security update according to
  Microsoft Bulletin MS08-056.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");

if(hotfix_check_sp(xp:4, win2k:5, win2003:3) <= 0){
  exit(0);
}

offVer = get_kb_item("MS/Office/Ver");
if(!offVer){
 exit(0);
}

if(offVer =~ "^10\.")
{
  if(registry_key_exists(key:"SOFTWARE\Classes\PROTOCOLS\Handler\cdo") &&
     registry_key_exists(key:"SOFTWARE\Classes\CDO")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

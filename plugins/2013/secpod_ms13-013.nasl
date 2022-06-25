###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft FAST Search Server 2010 SharePoint RCE Vulnerabilities (2784242)
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
  script_oid("1.3.6.1.4.1.25623.1.0.902949");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2012-3214", "CVE-2012-3217");
  script_bugtraq_id(55977, 55993);
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2013-02-13 11:28:37 +0530 (Wed, 13 Feb 2013)");
  script_name("Microsoft FAST Search Server 2010 SharePoint RCE Vulnerabilities (2784242)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/52136/");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2553234");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms13-013");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_fast_search_server_detect.nasl");
  script_mandatory_keys("MS/SharePoint/Install/Path");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation could run arbitrary code in the context of a user
  account with a restricted token.");
  script_tag(name:"affected", value:"Microsoft FAST Search Server 2010 for SharePoint Service Pack 1");
  script_tag(name:"insight", value:"The flaws are due to the error in Oracle Outside In libraries, when
  used by the Advanced Filter Pack while parsing specially crafted files.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS13-013.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## SharePoint Server 2010
path = get_kb_item("MS/SharePoint/Install/Path");
if(!path){
  exit(0);
}

dllPath = path + "bin";
dllVer = fetch_file_version(sysPath:dllPath,
         file_name:"Vseshr.dll");
if(!dllVer){
  exit(0);
}

if(version_in_range(version:dllVer, test_version:"8.3.7.000", test_version2:"8.3.7.206")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

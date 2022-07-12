###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_alzip_mim_bof_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# ALZip MIM File Processing Buffer Overflow Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802120");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-07-15 12:23:42 +0200 (Fri, 15 Jul 2011)");
  script_cve_id("CVE-2011-1336");
  script_bugtraq_id(48493);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("ALZip MIM File Processing Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/45108");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2011/JVNDB-2011-000048.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code in the
  context of the application. Failed attacks will cause denial-of-service
  conditions.");
  script_tag(name:"affected", value:"ALZip version 8.21 and prior.");
  script_tag(name:"solution", value:"Upgrade to version 8.21 published after June 29th, 2011  *****
  NOTE: Ignore this warning if above mentioned version is already installed.
  *****");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host has ALZip installed and is prone to buffer overflow
  vulnerability.

  Vulnerabilities Insight:
  The flaw is due to an error in libETC.dll when processing the
  'filename' field within MIM files.");
  script_xref(name:"URL", value:"http://www.altools.com/ALTools/ALZip.aspx");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\ESTsoft\ALZip";
if(!registry_key_exists(key:key)){
  exit(0);
}

alVer = registry_get_sz(key:key, item:"Version");
if(!alVer){
 exit(0);
}

## ALZip version 8.21(8.12)
if(version_is_less_equal(version:alVer, test_version:"8.12")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

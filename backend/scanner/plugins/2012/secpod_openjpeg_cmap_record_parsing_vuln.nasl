###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_openjpeg_cmap_record_parsing_vuln.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# OpenJPEG CMAP Record Parsing Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.903019");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2012-1499");
  script_bugtraq_id(52654);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-04-25 11:28:15 +0530 (Wed, 25 Apr 2012)");
  script_name("OpenJPEG CMAP Record Parsing Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48498/");
  script_xref(name:"URL", value:"http://openjpeg.googlecode.com/svn/branches/openjpeg-1.5/NEWS");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/msvr/msvr12-004#section1");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("General");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"insight", value:"The flaw is due to an error when parsing a CMAP record and can be
  exploited to cause an out of bounds write via specially crafted JPEG files.");
  script_tag(name:"solution", value:"Upgrade to the OpenJPEG version 1.5 or later.");
  script_tag(name:"summary", value:"This host is installed with OpenJPEG and is prone to record parsing
  vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code.");
  script_tag(name:"affected", value:"OpenJPEG version prior to 1.5");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://code.google.com/p/openjpeg/downloads/list");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\openjpeg";
if(!registry_key_exists(key:key)){
  exit(0);
}

openName = registry_get_sz(key:key, item:"DisplayName");
if("OpenJPEG" >< openName)
{
  openVer = registry_get_sz(key:key, item:"DisplayVersion");
  if(!openVer){
    exit(0);
  }

  if(version_is_less(version:openVer, test_version:"1.5")){
    security_message( port: 0, data: "The target host was found to be vulnerable" ) ;
    exit(0);
  }
}

exit(99);

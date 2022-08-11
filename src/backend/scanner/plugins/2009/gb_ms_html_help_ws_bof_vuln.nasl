###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_html_help_ws_bof_vuln.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# Microsoft HTML Help Workshop buffer overflow vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800505");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2009-01-19 13:47:40 +0100 (Mon, 19 Jan 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0133");
  script_bugtraq_id(33189);
  script_name("Microsoft HTML Help Workshop buffer overflow vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7727");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/366501.php");
  script_xref(name:"URL", value:"http://www.security-database.com/detail.php?alert=CVE-2009-0133");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful remote exploitation could context-dependent attackers
  to execute arbitrary code via a .hhp file with a long index file field.");
  script_tag(name:"affected", value:"Microsoft HTML Help Workshop 4.74 and prior on Windows.");
  script_tag(name:"insight", value:"A flaw is due to the way application handle a malformed HTML help workshop
  project.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running Microsoft HTML Help Workshop which is
  prone to buffer overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"http://office.microsoft.com/en-us/orkXP/HA011362801033.aspx");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

wsPath = registry_get_sz(item:"Path",
         key:"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\hhw.exe");
if(!wsPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:wsPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:wsPath + "\hhw.exe");

wsVer = GetVer(file:file, share:share);
if(!wsVer){
  exit(0);
}

if(version_is_less_equal(version:wsVer, test_version:"4.74.8702.0")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

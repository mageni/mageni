###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ultra_player_buf_overflow_vuln.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# UltraPlayer Media Player Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801207");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2010-05-19 14:50:39 +0200 (Wed, 19 May 2010)");
  script_bugtraq_id(35956);
  script_cve_id("CVE-2009-4863");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("UltraPlayer Media Player Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/52281");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2160");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9368");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute
arbitrary code within the context of the affected application.");
  script_tag(name:"affected", value:"UltraPlayer Media Player 2.112");
  script_tag(name:"insight", value:"The flaw is caused by improper bounds checking when parsing
malicious '.usk' files. By tricking a victim to open a specially crafted
.usk file, an attacker could exploit this vulnerability.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with UltraPlayer Media Player and is
  prone to buffer overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}



include("smb_nt.inc");
include("secpod_smb_func.inc");
include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

upPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                     "\App Paths\UPlayer.exe", item:"Path");
if(!upPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*",replace:"\1$", string:upPath);
file = ereg_replace(pattern:"[A-Z]:(.*)",replace:"\1",
                                        string:upPath + "\UPlayer.exe");

upVer = GetVer(share:share, file:file);

if(upVer)
{
  if(version_is_equal(version: upVer, test_version: "2.1.1.2")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

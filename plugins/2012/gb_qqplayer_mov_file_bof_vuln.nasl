###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_qqplayer_mov_file_bof_vuln.nasl 11374 2018-09-13 12:45:05Z asteins $
#
# QQPlayer MOV File Processing Buffer Overflow Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012  Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802367");
  script_version("$Revision: 11374 $");
  script_cve_id("CVE-2011-5006");
  script_bugtraq_id(50739);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-13 14:45:05 +0200 (Thu, 13 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-01-02 12:43:57 +0530 (Mon, 02 Jan 2012)");
  script_name("QQPlayer MOV File Processing Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://1337day.com/exploits/16899");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46924");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71368");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18137/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execution of
arbitrary code.");
  script_tag(name:"affected", value:"QQPlayer version 3.2.845 and prior.");
  script_tag(name:"insight", value:"The flaw is due to a boundary error when processing MOV files,
Which can be exploited to cause a stack based buffer overflow by sending
specially crafted MOV file with a malicious PnSize value.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with QQPlayer and is prone to buffer
overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

qqplName = "SOFTWARE\Tencent\QQPlayer";
if(!registry_key_exists(key:qqplName)){
  exit(0);
}

qqplVer = registry_get_sz(key:qqplName, item:"Version");
if(qqplVer != NULL)
{
  if(version_is_less_equal(version:qqplVer, test_version:"3.2.845.400")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

exit(99);

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_win_xp_chm_dos_vuln.nasl 12404 2018-11-19 08:40:38Z cfischer $
#
# Microsoft Windows XP SP3 denial of service vulnerability.
#
# Updated By: Antu Sanadi <santu@secpod.com> on 2011-09-22
# Updated the version check for itss.dll
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
  script_oid("1.3.6.1.4.1.25623.1.0.800504");
  script_version("$Revision: 12404 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-19 09:40:38 +0100 (Mon, 19 Nov 2018) $");
  script_tag(name:"creation_date", value:"2009-01-19 13:47:40 +0100 (Mon, 19 Jan 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0119");
  script_bugtraq_id(33204);
  script_name("Microsoft Windows XP SP3 denial of service vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7720");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful remote exploitation could result in administrator
access, unauthorized disclosure of information and disruption of service by
executing arbitrary code.");
  script_tag(name:"affected", value:"Microsoft Windows XP SP3 and prior.");
  script_tag(name:"insight", value:"The flaw is due to an error generated in Windows XP while
handling CHM files causing buffer overflow.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running Microsoft Windows XP which is prone to
denial of service vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(hotfix_check_sp(xp:4) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\itss.dll");
if(!dllVer){
  exit(0);
}

if(version_is_less_equal(version:dllVer, test_version:"5.2.3790.4186")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

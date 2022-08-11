###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ftp_voyager_dir_trav_vuln.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# FTP Voyager Directory Traversal Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.801627");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2010-11-04 14:21:53 +0100 (Thu, 04 Nov 2010)");
  script_bugtraq_id(43869);
  script_cve_id("CVE-2010-4154");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("FTP Voyager Directory Traversal Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41719");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/62392");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1010-exploits/ftpvoyager-traversal.txt");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to download or
upload arbitrary files. This may aid in further attacks.");
  script_tag(name:"affected", value:"FTP Voyager 15.2.0.11 and prior.");
  script_tag(name:"insight", value:"The flaw is due to an input validation error when downloading
directories containing files with directory traversal specifiers in the
filename. This can be exploited to download files to an arbitrary location
on a user's system.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with FTP Voyager and is prone to directory
traversal vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}



include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FTP Voyager_is1";
if(!registry_key_exists(key:key)){
  exit(0);
}

ftpPath = registry_get_sz(key:key, item:"Inno Setup: App Path");
if(!ftpPath) {
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*",replace:"\1$", string:ftpPath);
file = ereg_replace(pattern:"[A-Z]:(.*)",replace:"\1", string:ftpPath +
                                                      "\FTPVSetup.exe");

ftpVer = GetVer(share:share, file:file);
if(ftpVer)
{
  if(version_is_less_equal(version:ftpVer, test_version:"15.2.0.11")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

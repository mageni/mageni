###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_fsecure_prdts_sec_bypass_vuln_win.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# F-Secure Products Malware Detection Bypass Vulnerability (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900362");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2009-06-17 17:54:48 +0200 (Wed, 17 Jun 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1782");
  script_bugtraq_id(34849);
  script_name("F-Secure Products Malware Detection Bypass Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35008");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50346");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1262");
  script_xref(name:"URL", value:"http://www.f-secure.com/en_EMEA/support/security-advisory/fsc-2009-1.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Malware");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation will let the attacker craft malwares in a
  archive file and spread it across the network to gain access to sensitive
  information or cause damage to the system.");

  script_tag(name:"affected", value:"F-Secure Anti-Virus 2009 and earlier

  F-Secure Client Security 8.0 and earlier

  F-Secure Internet Security 2009 and earlier

  F-Secure Anti-Virus for MIMEsweeper 5.61 and earlier

  F-Secure Anti-Virus for Workstations 8.0 and earlier

  F-Secure Anti-Virus for Windows Servers 8.00 and earlier

  F-Secure Internet Gatekeeper for Windows 6.61 and earlier

  F-Secure Anti-Virus for Microsoft Exchange 7.10 and earlier");

  script_tag(name:"insight", value:"This flaw is due to bug in the antivirus scanning engine which doesn't process
  the malformed crafted malware archives.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"summary", value:"This host is installed with F-Secure Product and is prone to
  Malware Detection Bypass Vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Data Fellows\F-Secure")){
  exit(0);
}

# Anti-Virus for Windows Servers and Internet Security
fsPath = registry_get_sz(key:"SOFTWARE\Data Fellows\F-Secure\Anti-Virus",
                         item:"Path");
if(!fsPath)
{
  fsPath = registry_get_sz(key:"SOFTWARE\Data Fellows\F-Secure" +
                               "\Content Scanner Server", item:"Path");
  if(!fsPath){
    exit(0);
  }
}

fsPath = fsPath + "\fm4av.dll";
share = ereg_replace(pattern:"([a-zA-Z]):.*", replace:"\1$", string:fsPath);
file = ereg_replace(pattern:"[a-zA-Z]:(.*)", replace:"\1", string:fsPath);

dllVer = GetVer(file:file, share:share);
if(!dllVer){
  exit(0);
}

if(version_is_less(version:dllVer, test_version:"3.1.15160.1")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

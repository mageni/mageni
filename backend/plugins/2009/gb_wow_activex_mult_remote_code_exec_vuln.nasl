###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wow_activex_mult_remote_code_exec_vuln.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# WoW ActiveX Multiple Remote Code Execution Vulnerabilities
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800224");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2009-02-05 14:42:09 +0100 (Thu, 05 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0389");
  script_bugtraq_id(33515);
  script_name("WoW ActiveX Multiple Remote Code Execution Vulnerabilities");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7910");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/48337");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary codes in the
  context of the application and can compromise the affected remote system.");
  script_tag(name:"affected", value:"WoW ActiveX Control version 2 and prior on Windows.");
  script_tag(name:"insight", value:"Flaws are caused as WoW allows remote attackers to,

  - Create and overwrite arbitrary files via 'WriteIniFileString' method.

  - Execute arbitrary programs via the 'ShellExecute' method.

  - Read/Write from/to the registry via unspecified vectors.");
  script_tag(name:"summary", value:"This host is installed with WoW ActiveX and is prone to Multiple
  Remote Code Execution Vulnerabilities.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"http://www.eztools-software.com/tools/wow/default.asp");
  exit(0);
}


include("smb_nt.inc");
include("secpod_activex.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                            "\Uninstall\WOW2 ActiveX Control Sample_is1")){
  exit(0);
}

# Vulnerable CLASSID and killbit check
clsid = "{441E9D47-9F52-11D6-9672-0080C88B3613}";
if(is_killbit_set(clsid:clsid) == 0){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

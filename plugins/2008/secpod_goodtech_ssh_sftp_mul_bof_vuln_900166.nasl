##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_goodtech_ssh_sftp_mul_bof_vuln_900166.nasl 12602 2018-11-30 14:36:58Z cfischer $
# Description: GoodTech SSH Server SFTP Multiple BOF Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900166");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-10-31 14:50:32 +0100 (Fri, 31 Oct 2008)");
  script_cve_id("CVE-2008-4726");
  script_bugtraq_id(31879);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Denial of Service");
  script_name("GoodTech SSH Server SFTP Multiple BOF Vulnerabilities");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation allows execution of arbitrary code, and denial of
  service.");

  script_tag(name:"affected", value:"GoodTech SSH Server version 6.4 and prior on Windows (all)");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to GoodTech SSH Server version 6.5 or later.");

  script_tag(name:"summary", value:"The host is running GoodTech SSH server and is prone to multiple
  buffer overflow vulnerabilities.

  The flaws are due to error in SFTP 'open', 'opendir', and 'unlink'
  commands. This can be exploited by passing overly long string argument.");

  script_xref(name:"URL", value:"http://milw0rm.com/exploits/6804");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32375/");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/2895");
  script_xref(name:"URL", value:"http://www.goodtechsys.com/sshdnt2000.asp");

  exit(0);
}

include("smb_nt.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

sshVer = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\GoodTech SSH Server", item:"DisplayVersion");
if(sshVer){
  if(egrep(pattern:"^([0-5](\..*)|6\.[0-4])$", string:sshVer)){
    security_message(port:0);
  }
}

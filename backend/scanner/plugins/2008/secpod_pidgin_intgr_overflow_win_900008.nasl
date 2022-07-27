##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_pidgin_intgr_overflow_win_900008.nasl 12602 2018-11-30 14:36:58Z cfischer $
# Description: Pidgin MSN SLP Message Integer Overflow Vulnerabilities (Windows)
#
# Authors:
# Chandan S <schandan@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900008");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_bugtraq_id(29956);
  script_cve_id("CVE-2008-2927");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("General");
  script_name("Pidgin MSN SLP Message Integer Overflow Vulnerabilities (Windows)");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"affected", value:"Pidgin Version prior to 2.4.3 on Windows (All).");

  script_tag(name:"insight", value:"The flaw is due to errors in the msn_slplink_process_msg
  function in libpurple/protocols/msnp9/slplink.c and libpurple/protocols/msn/slplink.c files,
  which fails to perform adequate boundary checks on user-supplied data.");

  script_tag(name:"summary", value:"The host is running Pidgin, which is prone to integer
  overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to Pidgin Version 2.4.3.");

  script_tag(name:"impact", value:"Remote attacker can execute arbitrary code by sending
  specially crafted SLP message with the privilege of a user.");

  script_xref(name:"URL", value:"http://www.pidgin.im/news/security/?id=24");

  exit(0);
}

include("smb_nt.inc");

 if(!get_kb_item("SMB/WindowsVersion")){
        exit(0);
 }

 pidginVer = registry_get_sz(item:"DisplayVersion",
	     key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Pidgin");

 if(egrep(pattern:"^([01]\..*|2\.([0-3](\..*)?|4(\.[0-2])?))$", string:pidginVer)){
 	security_message( port: 0, data: "The target host was found to be vulnerable" );
 }

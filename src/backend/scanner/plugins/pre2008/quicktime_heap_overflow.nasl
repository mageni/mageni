###############################################################################
# OpenVAS Vulnerability Test
# $Id: quicktime_heap_overflow.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# Quicktime player/plug-in Heap overflow
#
# Authors:
# Jeff Adams <jadams@netcentrics.com>
#
# Copyright:
# Copyright (C) 2004 Jeff Adams
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.12226");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(10257);
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2004-0431");
  script_name("Quicktime player/plug-in Heap overflow");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 Jeff Adams");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"solution", value:"Uninstall this software or upgrade to version 6.5.1 or higher.");

  script_tag(name:"summary", value:"The remote host is using QuickTime, a popular media player/Plug-in
  which handles many Media files.");

  script_tag(name:"impact", value:"This version has a Heap overflow which may allow an attacker
  to execute arbitrary code on this host, with the rights of the user
  running QuickTime.");

  script_xref(name:"URL", value:"http://eeye.com/html/Research/Advisories/AD20040502.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

version = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Apple Computer, Inc./Quicktime/Version");
if ( version && version < 0x06100000 ) security_message(port:0);

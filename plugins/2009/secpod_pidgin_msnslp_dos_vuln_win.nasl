###############################################################################
# OpenVAS Vulnerability Test
#
# Pidgin MSN SLP Packets Denial Of Service Vulnerability (Windows)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900919");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2694");
  script_bugtraq_id(36071);
  script_name("Pidgin MSN SLP Packets Denial Of Service Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36384");
  script_xref(name:"URL", value:"http://www.pidgin.im/news/security/?id=34");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2303");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_pidgin_detect_win.nasl");
  script_mandatory_keys("Pidgin/Win/Ver");
  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary code, corrupt memory
  and cause the application to crash.");
  script_tag(name:"affected", value:"Pidgin version prior to 2.5.9 on Windows.");
  script_tag(name:"insight", value:"An error in the 'msn_slplink_process_msg()' function while processing
  malformed MSN SLP packets which can be exploited to overwrite of an
  arbitrary memory location.");
  script_tag(name:"solution", value:"Upgrade to Pidgin version 2.5.9.");
  script_tag(name:"summary", value:"This host has Pidgin installed and is prone to Denial of Service
  vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

pidginVer = get_kb_item("Pidgin/Win/Ver");
if(!pidginVer)
  exit(0);

if(version_is_less(version:pidginVer, test_version:"2.5.9")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

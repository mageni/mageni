###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pidgin_msnslp_dir_trav_vuln_win.nasl 14331 2019-03-19 14:03:05Z jschulte $
#
# Pidgin MSN Custom Smileys File Disclosure Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800421");
  script_version("$Revision: 14331 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:03:05 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-01-16 12:13:24 +0100 (Sat, 16 Jan 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-0013");
  script_name("Pidgin MSN Custom Smileys File Disclosure Vulnerability (Windows)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37953/");
  script_xref(name:"URL", value:"http://www.pidgin.im/news/security/?id=42");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3662");
  script_xref(name:"URL", value:"http://developer.pidgin.im/viewmtn/revision/info/c64a1adc8bda2b4aeaae1f273541afbc4f71b810");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_pidgin_detect_win.nasl");
  script_mandatory_keys("Pidgin/Win/Ver");
  script_tag(name:"impact", value:"Attackers can exploit this issue to gain knowledge of sensitive information
  via directory traversal attacks.");
  script_tag(name:"affected", value:"Pidgin version prior to 2.6.4 on Windows.");
  script_tag(name:"insight", value:"This issue is due to an error in 'slp.c' within the 'MSN protocol plugin'
  in 'libpurple' when processing application/x-msnmsgrp2p MSN emoticon (aka custom
  smiley) request.");
  script_tag(name:"summary", value:"This host has Pidgin installed and is prone to File Disclosure
  vulnerability");
  script_tag(name:"solution", value:"Apply the patch or upgrade to Pidgin version 2.6.5

  *****
  NOTE: Please ignore this warning if the patch is already applied.
  *****");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

pidginVer = get_kb_item("Pidgin/Win/Ver");
if(pidginVer != NULL)
{
  if(version_is_less(version:pidginVer, test_version:"2.6.5")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_incorrect_gui_display_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Microsoft Internet Explorer Incorrect GUI Display Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Updated By: Antu sanadi <santu@secpod.com> on 2011-05-18
#  - This plugin is invalidated by secpod_ms11-006.nasl
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801831");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-02-01 16:46:08 +0100 (Tue, 01 Feb 2011)");
  script_cve_id("CVE-2011-0347");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Internet Explorer Incorrect GUI Display Vulnerability");
  script_xref(name:"URL", value:"http://lcamtuf.coredump.cx/cross_fuzz/msie_display.jpg");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/advisory/2490606.mspx");
  script_xref(name:"URL", value:"http://lcamtuf.blogspot.com/2011/01/announcing-crossfuzz-potential-0-day-in.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_tag(name:"impact", value:"Successful exploits will allow an attacker to trigger an
incorrect GUI display and have unspecified other impact.");
  script_tag(name:"affected", value:"Microsoft Internet Explorer on Windows XP");
  script_tag(name:"insight", value:"The flaw is caused due an error which allows remote attackers to
trigger an incorrect GUI display and have unspecified other impact via vectors
related to the DOM implementation.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host has installed with Internet Explorer and is prone to
incorrect GUI display vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}


## This plugin is deprecated by secpod_ms11-006.nasl
exit(66);

include("secpod_reg.inc");
include("version_func.inc");

if(hotfix_check_sp(xp:4) <= 0){
  exit(0);
}

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

if(version_is_less_equal(version:ieVer, test_version:"8.0.6001.18702")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

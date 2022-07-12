# OpenVAS Vulnerability Test
# $Id: mozilla_certif_handle_dos.nasl 12621 2018-12-03 10:50:25Z cfischer $
# Description: Mozilla/Firefox security manager certificate handling DoS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
# Updated: 03/12/2009 Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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
#

#  Ref: Marcel Boesch <marboesc@student.ethz.ch>.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14668");
  script_version("$Revision: 12621 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 11:50:25 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(10703);
  script_cve_id("CVE-2004-0758");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Mozilla/Firefox security manager certificate handling DoS");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Windows");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  script_tag(name:"solution", value:"Upgrade to the latest version of this software");
  script_tag(name:"summary", value:"The remote host is using Mozilla, an alternative web browser.

  The Mozilla Personal Security Manager (PSM) contains  a flaw
  that may permit a attacker to import silently a certificate into
  the PSM certificate store.
  This corruption may result in a deny of SSL connections.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

mozVer = get_kb_item("Firefox/Win/Ver");
if(!mozVer){
  exit(0);
}

if(version_in_range(version:mozVer, test_version:"1.5", test_version2:"1.7")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}



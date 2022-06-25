###############################################################################
# OpenVAS Vulnerability Test
#
# WoW Raid Manager Cross-Site Scripting Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.900515");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-03-03 06:56:37 +0100 (Tue, 03 Mar 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2008-6161");
  script_bugtraq_id(31661);
  script_name("WoW Raid Manager Cross-Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32172");
  script_xref(name:"URL", value:"http://sourceforge.net/project/shownotes.php?release_id=631789");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("secpod_wow_raid_manager_detect.nasl");
  script_mandatory_keys("WoWRaidManager/Ver");
  script_tag(name:"impact", value:"Successful remote exploitation will let the attacker execute
  arbitrary code in the scope of the application. As a result the attacker
  may gain sensitive information and use it to redirect the user to any
  other malicious URL.");
  script_tag(name:"affected", value:"WoW Raid Manager versions prior to 3.5.1.");
  script_tag(name:"insight", value:"The flaw exists due to WoW Raid Manager fails to properly sanitise user
  supplied input.");
  script_tag(name:"solution", value:"Upgrade to version 3.5.1.");
  script_tag(name:"summary", value:"The host is installed with WoW Raid Manager and is prone to
  Cross-Site Scripting vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

wowVer = get_kb_item("WoWRaidManager/Ver");
if(!wowVer)
  exit(0);

if(version_is_less(version:wowVer, test_version:"3.5.1")){
  security_message(port:0);
}

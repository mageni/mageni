###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_south_river_webdrive_loc_priv_esc_vuln.nasl 12694 2018-12-06 15:28:57Z cfischer $
#
# South River Technologies WebDrive Local Privilege Escalation Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800159");
  script_version("$Revision: 12694 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-06 16:28:57 +0100 (Thu, 06 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-01-28 16:24:05 +0100 (Thu, 28 Jan 2010)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4606");
  script_name("South River Technologies WebDrive Local Privilege Escalation Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37083/");
  script_xref(name:"URL", value:"http://retrogod.altervista.org/9sg_south_river_priv.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/507323/100/0/threaded");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_south_river_webdrive_detect.nasl");
  script_mandatory_keys("SouthRiverWebDrive/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let the local attacker to execute arbitrary
  commands with an elevated privileges.");
  script_tag(name:"affected", value:"South River WebDrive version 9.02 build 2232 and prior on Windows.");
  script_tag(name:"insight", value:"The flaw is due to the WebDrive Service being installed without
  security descriptors, which could be exploited by local attackers to,

  - stop the service via the stop command

  - restart the service via the start command

  - execute arbitrary commands with elevated privileges by changing the
    service 'binPath' configuration.");
  script_tag(name:"solution", value:"Upgrade to South River WebDrive version 9.10 or later");
  script_tag(name:"summary", value:"This host is installed with South River Technologies WebDrive and
  is prone to Local Privilege Escalation Vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.webdrive.com/download/index.html");
  exit(0);
}


include("version_func.inc");

webDriveVer = get_kb_item("SouthRiverWebDrive/Win/Ver");
if(webDriveVer != NULL)
{
  if(version_is_less_equal(version:webDriveVer, test_version:"9.02.2232")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

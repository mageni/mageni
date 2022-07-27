###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_amsn_session_hijack_vuln_win.nasl 12694 2018-12-06 15:28:57Z cfischer $
#
# aMSN session hijack vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902045");
  script_version("$Revision: 12694 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-06 16:28:57 +0100 (Thu, 06 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-04-29 10:04:32 +0200 (Thu, 29 Apr 2010)");
  script_cve_id("CVE-2008-7255");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("aMSN session hijack vulnerability (Windows)");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/393176.php");
  script_xref(name:"URL", value:"http://www.amsn-project.net/forums/index.php?topic=5317.0");
  script_xref(name:"URL", value:"http://sourceforge.net/project/shownotes.php?release_id=610067");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("General");
  script_dependencies("secpod_amsn_detect_win.nasl");
  script_mandatory_keys("aMSN/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to hijack a session by visiting
  an unattended workstation.");
  script_tag(name:"affected", value:"aMSN vesrion prior to 0.97.1");
  script_tag(name:"insight", value:"The flaw is due to the error in 'login_screen.tcl' which saves a
  password after logout which allows attackers to hijack a session.");
  script_tag(name:"solution", value:"Upgrade to the aMSN version 0.97.1.");
  script_tag(name:"summary", value:"This host is installed with aMSN and is prone to session hijack
  vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://sourceforge.net/projects/amsn/files/");
  exit(0);
}


include("version_func.inc");

amsnVer = get_kb_item("aMSN/Win/Ver");

if(amsnVer != NULL)
{
  if(version_is_less(version:amsnVer, test_version:"0.97.1")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

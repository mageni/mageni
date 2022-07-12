###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ghostscript_cmd_exec_vuln.nasl 12673 2018-12-05 15:02:55Z cfischer $
#
# Ghostscript Arbitrary Command Execution Vulnerability.
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801412");
  script_version("$Revision: 12673 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-05 16:02:55 +0100 (Wed, 05 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-07-26 16:14:51 +0200 (Mon, 26 Jul 2010)");
  script_cve_id("CVE-2010-2055");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Ghostscript Arbitrary Command Execution Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_ghostscript_detect_win.nasl");
  script_mandatory_keys("Ghostscript/Win/Ver");

  script_xref(name:"URL", value:"http://secunia.com/advisories/40452");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1757");
  script_xref(name:"URL", value:"http://www.ghostscript.com");

  script_tag(name:"impact", value:"Successful exploitation allows the attackers to execute arbitrary
  postscript commands via the 'gs_init.ps' file, if a user is tricked into opening
  a file using the '-P-' option in an attacker controlled directory.");

  script_tag(name:"affected", value:"Ghostscript version 8.71 and prior");

  script_tag(name:"insight", value:"The flaw is due to, application reading certain postscript files
  in the current working directory although the '-P-' command line option is set.");

  script_tag(name:"solution", value:"Upgrade Ghostscript to version 9.0 or later.");

  script_tag(name:"summary", value:"This host is installed with Ghostscript and is prone to
  arbitrary command execution vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ghostVer = get_kb_item("Ghostscript/Win/Ver");
if(!ghostVer){
  exit(0);
}

if(version_is_less_equal(version:ghostVer, test_version:"8.71")){
   security_message( port: 0, data: "The target host was found to be vulnerable" );
}
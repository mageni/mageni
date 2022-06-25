###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_avast_av_insecure_lib_load_vul_win.nasl 12673 2018-12-05 15:02:55Z cfischer $
#
# Avast! Antivirus File Opening Insecure Library Loading Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902241");
  script_version("$Revision: 12673 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-05 16:02:55 +0100 (Wed, 05 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-09-01 09:34:36 +0200 (Wed, 01 Sep 2010)");
  script_cve_id("CVE-2010-3126");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Avast! Antivirus File Opening Insecure Library Loading Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41109");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14743/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2175");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("General");
  script_dependencies("gb_avast_av_detect_win.nasl");
  script_mandatory_keys("Avast!/AV/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow the attackers to execute
arbitrary code and conduct DLL hijacking attacks.");
  script_tag(name:"affected", value:"Avast! Antivirus version 5.0.594 and prior.");
  script_tag(name:"insight", value:"The flaw is due to the application insecurely loading certain
libraries from the current working directory, which could allow attackers
to execute arbitrary code by tricking a user into opening a license file.");
  script_tag(name:"solution", value:"Upgrade to version 5.0.677 or later.");
  script_tag(name:"summary", value:"This host is installed with avast! AntiVirus and is prone to
insecure library loading vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.avast.com/eng/download.html");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");

avastVer = get_kb_item("Avast!/AV/Win/Ver");
if(isnull(avastVer)){
  exit(0);
}

if(version_is_less_equal(version:avastVer, test_version:"5.0.594")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_realplayer_ivr_bof_vuln_win.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# RealNetworks RealPlayer IVR File Processing Buffer Overflow Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801768");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-1525");
  script_bugtraq_id(46946);
  script_name("RealNetworks RealPlayer IVR File Processing Buffer Overflow Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/43847");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/66209");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1025245");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_realplayer_detect_win.nasl");
  script_mandatory_keys("RealPlayer/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute
arbitrary code in the context of the vulnerable application. Failed exploit
attempts will result in a denial-of-service condition.");
  script_tag(name:"affected", value:"RealPlayer versions 14.0.2.633 and prior");
  script_tag(name:"insight", value:"The flaws are due to improper bounds checking by the
'rvrender.dll' when processing Internet Video Recording (IVR) files.");
  script_tag(name:"solution", value:"Upgrade to version 14.0.3 or later.");
  script_tag(name:"summary", value:"This host is installed with RealPlayer which is prone to Buffer
Overflow vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.real.com/player");
  exit(0);
}


include("version_func.inc");

rpVer = get_kb_item("RealPlayer/Win/Ver");
if(isnull(rpVer)){
  exit(0);
}

if(version_is_less_equal(version:rpVer, test_version:"12.0.1.633")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

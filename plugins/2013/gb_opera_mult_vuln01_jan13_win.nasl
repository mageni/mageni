###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_mult_vuln01_jan13_win.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Opera Multiple Vulnerabilities-01 Jan13 (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803138");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2012-6470", "CVE-2012-6471");
  script_bugtraq_id(56788, 56984);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-01-07 14:00:10 +0530 (Mon, 07 Jan 2013)");
  script_name("Opera Multiple Vulnerabilities-01 Jan13 (Windows)");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1038/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1040/");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/unified/1212/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_opera_detect_portable_win.nasl");
  script_mandatory_keys("Opera/Win/Version");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker crash the browser leading to
  denial of service, execute the arbitrary code or spoofing the address.");
  script_tag(name:"affected", value:"Opera version before 12.12 on Windows");
  script_tag(name:"insight", value:"- Malformed GIF images could allow execution of arbitrary code.

  - Repeated attempts to access a target site can trigger address field
    spoofing.");
  script_tag(name:"solution", value:"Upgrade to Opera version 12.12 or later.");
  script_tag(name:"summary", value:"The host is installed with Opera and is prone to multiple
  vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/Win/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less(version:operaVer, test_version:"12.12")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

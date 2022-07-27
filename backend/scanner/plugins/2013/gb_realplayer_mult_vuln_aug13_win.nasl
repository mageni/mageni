###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_realplayer_mult_vuln_aug13_win.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# RealNetworks RealPlayer Multiple Vulnerabilities August13 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803841");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-4973", "CVE-2013-4974");
  script_bugtraq_id(61989, 61990);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-08-29 10:15:44 +0530 (Thu, 29 Aug 2013)");
  script_name("RealNetworks RealPlayer Multiple Vulnerabilities August13 (Windows)");


  script_tag(name:"summary", value:"The host is installed with RealPlayer and is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to version 16.0.3.51 or later.");
  script_tag(name:"insight", value:"Flaws are due to errors when handling filenames in RMP and when parsing
RealMedia files.");
  script_tag(name:"affected", value:"RealPlayer version prior to 16.0.3.51 on Windows.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote unauthenticated attacker to obtain
sensitive information, cause a denial of service condition, or execute
arbitrary code with the privileges of the application.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54621");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/246524");
  script_xref(name:"URL", value:"http://service.real.com/realplayer/security/08232013_player/en");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_realplayer_detect_win.nasl");
  script_mandatory_keys("RealPlayer/Win/Ver");
  script_xref(name:"URL", value:"http://www.real.com/player");
  exit(0);
}


include("version_func.inc");

rpVer = get_kb_item("RealPlayer/Win/Ver");
if(!rpVer){
  exit(0);
}

if(version_is_less(version:rpVer, test_version:"16.0.3.51"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

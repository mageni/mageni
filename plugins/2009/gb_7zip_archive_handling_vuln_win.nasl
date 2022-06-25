###############################################################################
# OpenVAS Vulnerability Test
#
# 7-Zip Unspecified Archive Handling Vulnerability (Windows)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800261");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-04-02 08:15:32 +0200 (Thu, 02 Apr 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-6536");
  script_bugtraq_id(28285);
  script_name("7-Zip Unspecified Archive Handling Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/29434");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2008/0914/references");
  script_xref(name:"URL", value:"http://www.cert.fi/haavoittuvuudet/joint-advisory-archive-formats.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_7zip_detect_portable_win.nasl");
  script_mandatory_keys("7zip/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary code in the
  affected system and cause denial of service.");
  script_tag(name:"affected", value:"7zip version prior to 4.57 on Windows.");
  script_tag(name:"insight", value:"This flaw occurs due to memory corruption while handling malformed archives.");
  script_tag(name:"solution", value:"Upgrade to 7zip version 4.57.");
  script_tag(name:"summary", value:"This host is installed with 7zip and is prone to Unspecified
  vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

version = get_kb_item("7zip/Win/Ver");
if(!version)
  exit(0);

if(version_is_less(version:version, test_version:"4.57")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

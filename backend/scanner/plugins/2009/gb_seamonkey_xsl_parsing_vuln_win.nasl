###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Seamonkey XSL Parsing Vulnerability (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800380");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-04-08 08:04:29 +0200 (Wed, 08 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1169");
  script_bugtraq_id(34235);
  script_name("Mozilla Seamonkey XSL Parsing Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34471");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8285");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Mar/1021941.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-12.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_seamonkey_detect_win.nasl");
  script_mandatory_keys("Seamonkey/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker cause remote code execution
  through a specially crafted malicious XSL file or can cause application
  termination at runtime.");
  script_tag(name:"affected", value:"Mozilla Seamonkey version 1.0 to 1.1.15 on Windows.");
  script_tag(name:"insight", value:"This flaw is due to improper handling of errors encountered when transforming
  an XML document which can be exploited to cause memory corruption through a
  specially crafted XSLT code.");
  script_tag(name:"solution", value:"Upgrade to Seamonkey version 1.1.16 or later.");
  script_tag(name:"summary", value:"The host is installed with Mozilla Seamnkey and is prone to XSL
  File Parsing Vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

smVer = get_kb_item("Seamonkey/Win/Ver");
if(!smVer)
  exit(0);

if(version_in_range(version:smVer, test_version:"1.0",
                                   test_version2:"1.1.15")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

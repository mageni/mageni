###############################################################################
# OpenVAS Vulnerability Test
#
# Tor Unspecified Remote Memory Corruption Vulnerability (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.800352");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-02-06 13:48:17 +0100 (Fri, 06 Feb 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0414");
  script_bugtraq_id(33399);
  script_name("Tor Unspecified Remote Memory Corruption Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33635");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33677");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Jan/1021633.html");
  script_xref(name:"URL", value:"http://blog.torproject.org/blog/tor-0.2.0.33-stable-released");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_tor_detect_win.nasl");
  script_mandatory_keys("Tor/Win/Ver");
  script_tag(name:"affected", value:"Tor version prior to 0.2.0.33 on Windows.");
  script_tag(name:"insight", value:"Due to unknown impact, remote attackers can trigger heap corruption on
  the application.");
  script_tag(name:"solution", value:"Upgrade to version 0.2.0.33 or later.");
  script_tag(name:"summary", value:"This host is installed with Tor and is prone to unspecified remote
  Memory Corruption vulnerability.");
  script_tag(name:"impact", value:"A remote user could execute arbitrary code on the target system and can
  cause denial-of-service or compromise a vulnerable system.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

torVer = get_kb_item("Tor/Win/Ver");
if(!torVer)
  exit(0);

if(version_is_less(version:torVer, test_version:"0.2.0.33")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

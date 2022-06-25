###############################################################################
# OpenVAS Vulnerability Test
#
# G15Daemon Unspecified Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900854");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-09-18 08:01:03 +0200 (Fri, 18 Sep 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-7197");
  script_name("G15Daemon Unspecified Vulnerability");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/apps/freshmeat/2008-01/0019.html");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("secpod_g15daemon_detect.nasl");
  script_mandatory_keys("G15Daemon/Ver");
  script_tag(name:"impact", value:"Unknown impact.");
  script_tag(name:"affected", value:"G15Daemon version prior to 1.9.4");
  script_tag(name:"insight", value:"Multiple unspecified vulnerabilities exist, details are not available.");
  script_tag(name:"solution", value:"Upgrade to version 1.9.4 or later.");
  script_tag(name:"summary", value:"This host has G15Daemon installed and is prone to Unspecified
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

g15dVer = get_kb_item("G15Daemon/Ver");
if(!g15dVer)
  exit(0);

if(version_is_less(version:g15dVer, test_version:"1.9.4")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

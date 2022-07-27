###############################################################################
# OpenVAS Vulnerability Test
#
# libpng pngwutil.c NULL pointer Vulnerability
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.org
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
  script_oid("1.3.6.1.4.1.25623.1.0.900071");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-01-22 12:00:13 +0100 (Thu, 22 Jan 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2008-5907");
  script_name("libpng pngwutil.c NULL pointer Vulnerability");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2009/01/09/1");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("secpod_libpng_detect_lin.nasl");
  script_mandatory_keys("Libpng/Version");
  script_tag(name:"impact", value:"Successful remote exploitation could result in arbitrary code execution
  on the affected system.");
  script_tag(name:"affected", value:"libpng 1.0.41 and prior and 1.2.x to 1.2.33 on Linux.");
  script_tag(name:"insight", value:"Attackers can set the value of arbitrary memory location to zero via
  vectors involving creation of crafted PNG files with keywords, related
  to an implicit cast of the '\0' character constant to a NULL pointer.");
  script_tag(name:"solution", value:"Upgrade to libpng 1.0.42 or 1.2.34.");
  script_tag(name:"summary", value:"The host has libpng installed and is prone to memory overwrite
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

pngVer = get_kb_item("Libpng/Version");
if(!pngVer)
  exit(0);

if(version_is_less_equal(version:pngVer, test_version:"1.0.41")||
   version_in_range(version:pngVer, test_version:"1.2.0", test_version2:"1.2.33")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

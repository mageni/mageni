###############################################################################
# OpenVAS Vulnerability Test
#
# OpenOffice EMF Files Multiple Buffer Overflow Vulnerabilities (Windows)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900954");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-09-24 10:05:51 +0200 (Thu, 24 Sep 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2140");
  script_name("OpenOffice EMF Files Multiple Buffer Overflow Vulnerabilities (Windows)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_openoffice_detect_win.nasl");
  script_mandatory_keys("OpenOffice/Win/Ver");
  script_tag(name:"impact", value:"Successful remote exploitation could result in arbitrary code execution.");
  script_tag(name:"affected", value:"OpenOffice 2.x and 3.x before 3.0.1 on Windows.");
  script_tag(name:"insight", value:"The Multiple flaws are due to buffer overflow error in cppcanvas/source/
  mtfrenderer/emfplus.cxx when processing crafted EMF+ files.");
  script_tag(name:"solution", value:"Upgrade to OpenOffice 3.0.1 or later.");
  script_tag(name:"summary", value:"The host has OpenOffice installed and is prone to Multiple Buffer
  Overflow vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://marc.info/?l=oss-security&m=125258116800739&w=2");
  script_xref(name:"URL", value:"http://marc.info/?l=oss-security&m=125265261125765&w=2");
  exit(0);
}

include("version_func.inc");

openVer = get_kb_item("OpenOffice/Win/Ver");
if(!openVer)
  exit(0);

if(openVer =~ "^[23]\.")
{
  if(version_is_less(version:openVer, test_version:"3.0.1")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

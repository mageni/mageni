###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_libreoffice_graphic_object_bof_vuln_win.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# LibreOffice Graphic Object Loading Buffer Overflow Vulnerability (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803084");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2012-1149");
  script_bugtraq_id(53570);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-12-24 16:32:25 +0530 (Mon, 24 Dec 2012)");
  script_name("LibreOffice Graphic Object Loading Buffer Overflow Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47244");
  script_xref(name:"URL", value:"http://www.libreoffice.org/advisories/cve-2012-1149");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_libreoffice_detect_portable_win.nasl");
  script_mandatory_keys("LibreOffice/Win/Ver");
  script_tag(name:"insight", value:"An integer overflow error within the vclmi.dll module when allocating memory
  for an embedded image object allows attacker to crash the application.");
  script_tag(name:"solution", value:"Upgrade to LibreOffice version 3.5.3 or later.");
  script_tag(name:"summary", value:"This host is installed with LibreOffice and is prone to buffer
  overflow vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of
  service condition or execute arbitrary code.");
  script_tag(name:"affected", value:"LibreOffice version before 3.5.3 on Windows");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.libreoffice.org/download/");
  exit(0);
}

include("version_func.inc");

libreVer = get_kb_item("LibreOffice/Win/Ver");
if(!libreVer){
  exit(0);
}

if(version_is_less(version: libreVer, test_version:"3.5.3")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

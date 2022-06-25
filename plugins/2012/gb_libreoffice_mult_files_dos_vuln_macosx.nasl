###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_libreoffice_mult_files_dos_vuln_macosx.nasl 11855 2018-10-12 07:34:51Z cfischer $
#
# LibreOffice Import Files Denial of Service Vulnerabilities (Mac OS X)
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
  script_oid("1.3.6.1.4.1.25623.1.0.803065");
  script_version("$Revision: 11855 $");
  script_cve_id("CVE-2012-4233");
  script_bugtraq_id(56352);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 09:34:51 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-11-26 14:04:53 +0530 (Mon, 26 Nov 2012)");
  script_name("LibreOffice Import Files Denial of Service Vulnerabilities (Mac OS X)");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027727");
  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB23106");
  script_xref(name:"URL", value:"http://www.libreoffice.org/advisories/cve-2012-4233/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_libreoffice_detect_macosx.nasl");
  script_mandatory_keys("LibreOffice/MacOSX/Installed");
  script_tag(name:"insight", value:"The flaws exist in multiple import files, which allows attacker to crash
  the application via a crafted file in the .xls (Excel), .wmf
  (Window Meta File) or Open Document Format files.");
  script_tag(name:"solution", value:"Upgrade to LibreOffice version 3.5.7.2 or 3.6.1 or later.");
  script_tag(name:"summary", value:"This host is installed with LibreOffice and is prone to denial of
  service vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of
  service condition.");
  script_tag(name:"affected", value:"LibreOffice version 3.5.x before 3.5.7.2 and 3.6.x before 3.6.1 on Mac OS X");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.libreoffice.org/download/");
  exit(0);
}

include("version_func.inc");

officeVer = get_kb_item("LibreOffice/MacOSX/Version");
buildVer = get_kb_item("LibreOffice-Build/MacOSX/Version");
if(!officeVer && !buildVer){
  exit(0);
}

if((officeVer =~ "^3\.6\.0") ||
   (buildVer && version_in_range(version:buildVer, test_version:"3.5", test_version2:"3.5.7.1"))){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

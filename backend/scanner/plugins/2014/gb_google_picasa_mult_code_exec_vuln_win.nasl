###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_picasa_mult_code_exec_vuln_win.nasl 2014-01-20 17:01:32Z jan$
#
# Google Picasa Multiple Code Execution Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:google:picasa";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804185");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2013-5349", "CVE-2013-5357", "CVE-2013-5358", "CVE-2013-5359");
  script_bugtraq_id(64467, 64468, 64466, 64470);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-01-20 11:18:19 +0530 (Mon, 20 Jan 2014)");
  script_name("Google Picasa Multiple Code Execution Vulnerabilities");


  script_tag(name:"summary", value:"This host is installed with Google Picasa and is prone to multiple
code execution vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaws are due to,

  - An integer underflow error within the 'Picasa3.exe' module when parsing
 JPEG tags.

  - An integer overflow error within the 'Picasa3.exe' module when parsing
 TIFF tags.

  - A boundary error within the 'Picasa3.exe' module when parsing TIFF tags.

  - An error within the 'Picasa3.exe' module when parsing RAW files.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to trigger memory
corruption and cause execution of arbitrary code.");
  script_tag(name:"affected", value:"Google Picasa before version 3.9.0 build 137.69 on Windows");
  script_tag(name:"solution", value:"Upgrade to version 3.9.0 build 137.69 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55555");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1029527");
  script_xref(name:"URL", value:"https://support.google.com/picasa/answer/53209");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_picasa_detect_win.nasl");
  script_mandatory_keys("Google/Picasa/Win/Ver");
  script_xref(name:"URL", value:"http://picasa.google.com");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!picVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:picVer, test_version:"3.9.137.69"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

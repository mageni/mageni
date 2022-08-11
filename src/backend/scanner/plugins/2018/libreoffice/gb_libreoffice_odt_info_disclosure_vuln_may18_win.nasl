###############################################################################
# OpenVAS Vulnerability Test
#
# LibreOffice ODT File Information Disclosure Vulnerability May18 (Windows)
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation;
# either version 2 of the License, or (at your option) any later version.
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

CPE = "cpe:/a:libreoffice:libreoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812872");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-10583");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-05-07 13:33:47 +0530 (Mon, 07 May 2018)");
  script_tag(name:"qod_type", value:"registry");

  script_name("LibreOffice ODT File Information Disclosure Vulnerability May18 (Windows)");

  script_tag(name:"summary", value:"This host is installed with LibreOffice and
  is prone to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists within an office:document-content element in a .odt XML
document.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to automatically process and
initiate an SMB connection embedded in a malicious .odt file and leak NetNTLM credentials.");

  script_tag(name:"affected", value:"LibreOffice prior to version 5.4.7 or 6.0.4 on Windows.");

  script_tag(name:"solution", value:"Update to version 5.4.7, 6.0.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secureyourit.co.uk/wp/2018/05/01/creating-malicious-odt-files/");
  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2018-10583/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_libreoffice_detect_portable_win.nasl");
  script_mandatory_keys("LibreOffice/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
lver = infos['version'];
lpath = infos['location'];

if (version_is_less(version: lver, test_version: "5.4.7")) {
  report = report_fixed_ver(installed_version:lver, fixed_version:"5.4.7", install_path:lpath);
  security_message(port: 0, data:report);
  exit(0);
}

if (lver =~ "^6\.0") {
  if (version_is_less(version: lver, test_version: "6.0.4")) {
    report = report_fixed_ver(installed_version:lver, fixed_version:"6.0.4", install_path:lpath);
    security_message(port: 0, data:report);
    exit(0);
  }
}

exit(0);

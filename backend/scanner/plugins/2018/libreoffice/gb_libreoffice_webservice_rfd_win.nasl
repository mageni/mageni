###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_libreoffice_webservice_rfd_win.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# LibreOffice 'WEBSERVICE formula' Remote File Disclosure Vulnerability (Windows)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:libreoffice:libreoffice";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108332");
  script_version("$Revision: 12116 $");
  script_cve_id("CVE-2018-6871");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-02-12 12:24:46 +0100 (Mon, 12 Feb 2018)");
  script_name("LibreOffice 'WEBSERVICE formula' Remote File Disclosure Vulnerability (Windows)");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_libreoffice_detect_portable_win.nasl");
  script_mandatory_keys("LibreOffice/Win/Ver");

  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2018-1055/");
  script_xref(name:"URL", value:"https://github.com/jollheef/libreoffice-remote-arbitrary-file-disclosure");

  script_tag(name:"summary", value:"The host is installed with LibreOffice
  and is prone to a remote file disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers
  to read arbitrary files via WEBSERVICE calls in a document, which use the
  COM.MICROSOFT.WEBSERVICE function.");

  script_tag(name:"affected", value:"LibreOffice versions before 5.4.5 and 6.x before 6.0.1.");

  script_tag(name:"solution", value:"Upgrade to LibreOffice version 5.4.5, 6.0.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.libreoffice.org");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
vers = infos['version'];
path = infos['location'];

if( vers =~ "^5\." && version_is_less( version:vers, test_version:"5.4.5") ) {
  fix = "5.4.5 or 6.0.1";
}

if( vers =~ "^6\." && version_is_less( version:vers, test_version:"6.0.1") ) {
  fix = "6.0.1";
}

if( fix ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix, install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

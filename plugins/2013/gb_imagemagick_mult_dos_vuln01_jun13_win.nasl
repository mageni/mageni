###############################################################################
# OpenVAS Vulnerability Test
#
# ImageMagick Multiple Denial of Service Vulnerabilities - 01 June13 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:imagemagick:imagemagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803815");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2012-0260", "CVE-2012-0259", "CVE-2012-1798");
  script_bugtraq_id(52898);
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2013-06-24 12:32:12 +0530 (Mon, 24 Jun 2013)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("ImageMagick Multiple Denial of Service Vulnerabilities - 01 June13 (Windows)");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2012/q2/19");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/74659");
  script_xref(name:"URL", value:"http://www.cert.fi/en/reports/2012/vulnerability635606.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_imagemagick_detect_win.nasl");
  script_mandatory_keys("ImageMagick/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation will allow a context-dependent attacker to cause
  denial of service result in loss of availability for the application.");
  script_tag(name:"affected", value:"ImageMagick version before 6.7.6-3 on Windows.");
  script_tag(name:"insight", value:"Multiple flaw are due to an,

  - Improper handling of JPEG restart markers of the 'JPEGWarningHandler()'
    function in coders/jpeg.c

  - Improper handling a JPEG EXIF tag of the 'GetEXIFProperty()' function
    in magick/property.c

  - Error occurs when parsing TIFF EXIF IFD of the 'TIFFGetEXIFProperties()'
    function in coders/tiff.c");
  script_tag(name:"solution", value:"Upgrade to ImageMagick version 6.7.6-3 or later.");
  script_xref(name:"URL", value:"http://www.imagemagick.org/script/download.php");
  script_tag(name:"summary", value:"The host is installed with ImageMagick and is prone to multiple
  denial of service Vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if( version_is_less( version:vers, test_version:"6.7.6.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"6.7.6.3", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
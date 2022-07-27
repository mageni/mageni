###############################################################################
# OpenVAS Vulnerability Test
#
# ImageMagick Integer Overflow Vulnerability - 03 June (Windows)
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
  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to cause denial of service
  condition result in loss of availability for the application.");
  script_tag(name:"affected", value:"ImageMagick version 6.7.5-8 and earlier on Windows.");
  script_tag(name:"insight", value:"Integer overflow error is due to an improper verification of executable file
  by profile.c");
  script_tag(name:"solution", value:"Upgrade to ImageMagick version 6.7.5-9 or later.");
  script_xref(name:"URL", value:"http://www.imagemagick.org/script/download.php");
  script_tag(name:"summary", value:"The host is installed with ImageMagick and is prone to integer
  overflow Vulnerability.");
  script_oid("1.3.6.1.4.1.25623.1.0.803818");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2012-1186");
  script_bugtraq_id(51957);
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2013-06-24 14:42:53 +0530 (Mon, 24 Jun 2013)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("ImageMagick Integer Overflow Vulnerability - 03 June (Windows)");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/76139");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2012/03/19/5");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_imagemagick_detect_win.nasl");
  script_mandatory_keys("ImageMagick/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if( version_is_less( version:vers, test_version:"6.7.5.9" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"6.7.5.9", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
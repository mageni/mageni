# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.107610");
  script_version("$Revision: 14134 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 10:46:53 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-03-09 20:32:14 +0100 (Sat, 09 Mar 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");
  script_cve_id("CVE-2018-16749", "CVE-2019-7395", "CVE-2019-7396", "CVE-2019-7397", "CVE-2019-7398");
  script_bugtraq_id(106561, 106847, 106848, 106849, 106850);

  script_name("ImageMagick < 7.0.8-25 Multiple Vulnerabilities (Mac OS X)");
  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_imagemagick_detect_macosx.nasl");
  script_mandatory_keys("ImageMagick/MacOSX/Version");
  script_tag(name:"summary", value:"ImageMagick is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - A denial of service (DoS) vulnerability exists in coders/png.c due to a missing null check, a memory leak.

  - A denial of service (DoS) vulnerability exists in coders/sixel.c due to a memory leak in ReadSIXELImage.

  - A denial of service (DoS) vulnerability exists in coders/pdf.c due to a memory leak in WritePDFImage.

  - A denial of service (DoS) vulnerability exists in coders/dib.c due to a memory leak in WriteDIBImage.");

  script_tag(name:"impact", value:"An unauthenticated, remote attacker can exploit these issues to cause the
  application to stop responding.");

  script_tag(name:"affected", value:"ImageMagick prior to version 7.0.8-25.");
  script_tag(name:"solution", value:"Upgrade to ImageMagick version 7.0.8-25 or later.");

  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1119");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1451");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1452");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1453");
  script_xref(name:"URL", value:"https://github.com/ImageMagick/ImageMagick/issues/1454");

  exit(0);
}

CPE = "cpe:/a:imagemagick:imagemagick";

include( "host_details.inc" );
include( "version_func.inc" );

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);

vers = infos['version'];
path = infos['location'];

if(version_is_less(version: vers, test_version: "7.0.8.25")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "7.0.8.25", install_path: path);
  security_message(data: report, port: 0);
  exit(0);
}

exit(99);

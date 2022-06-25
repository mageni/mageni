# Copyright (C) 2019 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113413");
  script_version("2019-06-20T09:19:59+0000");
  script_tag(name:"last_modification", value:"2019-06-20 09:19:59 +0000 (Thu, 20 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-20 10:52:47 +0000 (Thu, 20 Jun 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2019-10018", "CVE-2019-10019", "CVE-2019-10020", "CVE-2019-10021", "CVE-2019-10022", "CVE-2019-10023", "CVE-2019-10024", "CVE-2019-10025", "CVE-2019-10026");

  script_name("Xpdf <= 4.01.01 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_xpdf_detect.nasl");
  script_mandatory_keys("Xpdf/Linux/Ver");

  script_tag(name:"summary", value:"Xpdf is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Following vulnerabilities exist:

  - FPE in the function PostScriptFunction::exec at Function.cc for the psOpIdiv case

  - FPE in the function PSOutputDev::checkPageSlice at PSOutputDev.cc for nStripes

  - FPE in the function Splash::scaleImageYuXu at Splash.cc for x Bresenham parameters

  - FPE in the function ImageStream::ImageStream at Stream.cc for nComps

  - NULL pointer dereference in the function Gfx::opSetExtGState in Gfx.cc

  - FPE in the function PostScriptFunction::exec at Function.cc for the psOpMod case

  - FPE in the function Splash::scaleImageYuXu at Splash.cc for y Bresenham parameters

  - FPE in the function ImageStream::ImageStream at Stream.cc for nBits

  - FPE in the function PostScriptFunction::exec in Function.cc for the psOpRoll case");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to crash the application.");
  script_tag(name:"affected", value:"Xpdf through version 4.01.01.");
  script_tag(name:"solution", value:"No known solution is available as of 20th June, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://forum.xpdfreader.com/viewtopic.php?f=3&t=41273");
  script_xref(name:"URL", value:"https://forum.xpdfreader.com/viewtopic.php?f=3&t=41274");
  script_xref(name:"URL", value:"https://forum.xpdfreader.com/viewtopic.php?f=3&t=41275");
  script_xref(name:"URL", value:"https://forum.xpdfreader.com/viewtopic.php?f=3&t=41276");

  exit(0);
}

CPE = "cpe:/a:foolabs:xpdf";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "4.01.01" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None Available", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );

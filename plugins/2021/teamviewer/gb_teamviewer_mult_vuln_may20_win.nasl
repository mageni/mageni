# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

CPE = "cpe:/a:teamviewer:teamviewer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117251");
  script_version("2021-03-17T08:35:36+0000");
  script_cve_id("CVE-2019-18988");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-03-17 11:26:15 +0000 (Wed, 17 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-16 13:52:40 +0000 (Tue, 16 Mar 2021)");
  script_name("TeamViewer Multiple Vulnerabilities (CVE-2019-18988) - Windows");
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_teamviewer_win_detect.nasl");
  script_mandatory_keys("teamviewer/Ver");

  script_xref(name:"URL", value:"https://community.teamviewer.com/English/discussion/90813/windows-v14-7-39531-full-change-log");
  script_xref(name:"URL", value:"https://community.teamviewer.com/English/discussion/90812/windows-v14-2-56674-full-change-log");
  script_xref(name:"URL", value:"https://community.teamviewer.com/English/discussion/90811/windows-v13-2-36218-full-change-log");
  script_xref(name:"URL", value:"https://community.teamviewer.com/English/discussion/90810/windows-v12-0-251385-full-change-log");
  script_xref(name:"URL", value:"https://community.teamviewer.com/English/discussion/90809/windows-v11-0-252065-full-change-log");
  script_xref(name:"URL", value:"https://community.teamviewer.com/English/discussion/90808/windows-v10-0-252068-full-change-log");
  script_xref(name:"URL", value:"https://community.teamviewer.com/English/discussion/90804/windows-v9-0-252029-full-change-log");
  script_xref(name:"URL", value:"https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988");
  script_xref(name:"URL", value:"https://whynotsecurity.com/blog/teamviewer/");

  script_tag(name:"summary", value:"TeamViewer is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"The update has fixed an issue raised in CVE-2019-18988
  (Proxy password & Options password).

  Note that this update might also include various additional vulnerabilities tracked in
  the related CVE. However there is no clear communication by the vendor which
  vulnerabilities mentioned in the CVE are fixed in which release.

  Please see the references for more technical details.");

  script_tag(name:"affected", value:"TeamViewer versions 7.0.43148 through 14.7.x.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the
  references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_greater_equal( version:version, test_version:"7.0.43148" ) &&
    version_is_less( version:version, test_version:"9.0.252029" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"9.0.252029", install_path:location );
  security_message( port:0, data:report );
  exit( 0 );
}

else if( version =~ "^10\.0" && version_is_less( version:version, test_version:"10.0.252068" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"10.0.252068", install_path:location );
  security_message( port:0, data:report );
  exit( 0 );
}

else if( version =~ "^11\.0" && version_is_less( version:version, test_version:"11.0.252065" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"11.0.252065", install_path:location );
  security_message( port:0, data:report );
  exit( 0 );
}

else if( version =~ "^12\.0" && version_is_less( version:version, test_version:"12.0.137769" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"12.0.137769", install_path:location );
  security_message( port:0, data:report );
  exit( 0 );
}

else if( version =~ "^13\.[0-2]" && version_is_less( version:version, test_version:"13.2.36218" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"13.2.36218", install_path:location );
  security_message( port:0, data:report );
  exit( 0 );
}

else if( version =~ "^14\.[0-2]" && version_is_less( version:version, test_version:"14.2.56674" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.2.56674", install_path:location );
  security_message( port:0, data:report );
  exit( 0 );
}

else if( version =~ "^14\.[3-7]" && version_is_less( version:version, test_version:"14.7.39531" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.7.39531", install_path:location );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

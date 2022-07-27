# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108743");
  script_version("2020-04-07T11:55:55+0000");
  script_tag(name:"last_modification", value:"2020-04-08 11:51:46 +0000 (Wed, 08 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-03 11:41:58 +0000 (Fri, 03 Apr 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2018-20872");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("DrayTek Vigor Devices 'CVE-2018-20872' CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_draytek_vigor_consolidation.nasl");
  script_mandatory_keys("draytek/vigor/detected");

  script_tag(name:"summary", value:"Multiple DrayTek Vigor Routers are prone to a cross-site request forgery
  (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple DrayTek Vigor Routers allowing CSRF attacks to change DNS or DHCP settings.");

  script_tag(name:"affected", value:"Multiple DrayTek Vigor devices. Please see the referenced vendor advisory for a full
  list of affected devices.");

  script_tag(name:"solution", value:"The vendor has released firmware updates. Please see the referenced vendor advisory for a full
  list of released updates.");

  script_xref(name:"URL", value:"https://www.draytek.com/about/security-advisory/urgent-security-updates-to-draytek-routers");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:draytek:vigor2820_firmware",
                     "cpe:/o:draytek:vigor120_v2_firmware",
                     "cpe:/o:draytek:vigor2110_firmware",
                     "cpe:/o:draytek:vigor2710_firmware",
                     "cpe:/o:draytek:vigor2710e_firmware",
                     "cpe:/o:draytek:vigor2710ne_firmware",
                     "cpe:/o:draytek:vigor2120_firmware",
                     "cpe:/o:draytek:vigor2133_firmware",
                     "cpe:/o:draytek:vigor2760d_firmware",
                     "cpe:/o:draytek:vigor2762_firmware",
                     "cpe:/o:draytek:vigor2830_firmware",
                     "cpe:/o:draytek:vigor2830nv2_firmware",
                     "cpe:/o:draytek:vigor2832_firmware",
                     "cpe:/o:draytek:vigor2850_firmware",
                     "cpe:/o:draytek:vigor2862_firmware",
                     "cpe:/o:draytek:vigor2862b_firmware",
                     "cpe:/o:draytek:vigor2912_firmware",
                     "cpe:/o:draytek:vigor2920_firmware",
                     "cpe:/o:draytek:vigor2925_firmware",
                     "cpe:/o:draytek:vigor2926_firmware",
                     "cpe:/o:draytek:vigor2952_firmware",
                     "cpe:/o:draytek:vigor3200_firmware",
                     "cpe:/o:draytek:vigor3220_firmware",
                     "cpe:/o:draytek:vigor2860_firmware",
                     "cpe:/o:draytek:vigorbx2000_firmware",
                     "cpe:/o:draytek:vigor2820_firmware",
                     "cpe:/o:draytek:vigor120_v2_firmware",
                     "cpe:/o:draytek:vigor2110_firmware",
                     "cpe:/o:draytek:vigor2710_firmware",
                     "cpe:/o:draytek:vigor2710e_firmware",
                     "cpe:/o:draytek:vigor2710ne_firmware");

if( ! infos = get_app_version_from_list( cpe_list:cpe_list, nofork:TRUE ) )
  exit( 0 );

cpe = infos["cpe"];
ver = infos["version"];

if( cpe =~ "vigor(2120|2133|2760d|2762|2830|2830nv2|2832|2850|2862|2862b|2912|2920|2925|2926|2952|3200|3220)_firmware" )
  fix = "3.8.8.2";
else if( "vigor2860_firmware" >< cpe )
  fix = "3.8.8";
else if( "vigorbx2000_firmware" >< cpe )
  fix = "3.8.1.9";
else if( cpe =~ "vigor(2820|120_v2|2110|2710|2710e|2710ne)_firmware" )
  fix = "3.7.2";
else
  exit( 0 ); # nb: Shouldn't happen as long as a new CPE added to the cpe_list() was added to the checks above...

if( version_is_less( version:ver, test_version:fix ) ) {
  report = report_fixed_ver( installed_version:ver, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

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

CPE = "cpe:/o:avm:fritz%21_os";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117424");
  script_version("2021-05-14T07:53:11+0000");
  script_cve_id("CVE-2020-24586", "CVE-2020-24588");
  script_tag(name:"cvss_base", value:"2.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-05-14 09:39:56 +0000 (Fri, 14 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-14 07:43:49 +0000 (Fri, 14 May 2021)");
  script_name("AVM FRITZ!Box Multiple Wi-Fi Vulnerabilities (FragAttacks)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_dependencies("gb_avm_fritz_box_detect.nasl");
  script_mandatory_keys("avm/fritz/model", "avm/fritz/firmware_version");

  script_xref(name:"URL", value:"https://en.avm.de/service/current-security-notifications/");
  script_xref(name:"URL", value:"https://en.avm.de/service/security-information-about-updates/");
  script_xref(name:"URL", value:"https://www.fragattacks.com");

  script_tag(name:"summary", value:"AVM FRITZ!Box devices are prone to multiple Wi-Fi
  vulnerabilities.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2020-24586: fragment cache attack (not clearing fragments from memory when (re)connecting to
  a network)

  - CVE-2020-24588: aggregation attack (accepting non-SPP A-MSDU frames)");

  script_tag(name:"impact", value:"An adversary that is within radio range of a victim can abuse
  these vulnerabilities to steal user information or attack devices.");

  script_tag(name:"affected", value:"AVM FRITZ!Box devices running AVM FRITZ!OS before version 7.27.");

  script_tag(name:"vuldetect", value:"Checks the AVM FRITZ!OS version.");

  script_tag(name:"solution", value:"Update to AVM FRITZ!OS 7.27 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! fw_version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( ! model = get_kb_item( "avm/fritz/model" ) )
  exit( 0 );

if( version_is_less( version:fw_version, test_version:"7.27" ) ) {
  report  = 'Model:              ' + model + '\n';
  report += 'Installed Firmware: ' + fw_version + '\n';
  report += "Fixed Firmware:     7.27";
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108952");
  script_version("2020-10-20T06:44:37+0000");
  script_cve_id("CVE-2020-3702");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-10-20 10:21:19 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-20 06:19:45 +0000 (Tue, 20 Oct 2020)");
  script_name("AVM FRITZ!Box < 7.20 'Beyond Kr00k' Information Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_dependencies("gb_avm_fritz_box_detect.nasl");
  script_mandatory_keys("avm/fritz/model", "avm/fritz/firmware_version");

  script_xref(name:"URL", value:"https://en.avm.de/service/current-security-notifications/");
  script_xref(name:"URL", value:"https://www.welivesecurity.com/2020/08/06/beyond-kr00k-even-more-wifi-chips-vulnerable-eavesdropping/");

  script_tag(name:"summary", value:"Multiple AVM FRITZ!Box devices are prone to an information disclosure vulnerability.");

  script_tag(name:"insight", value:"An issue was discovered on Qualcomm Wi-Fi client devices. Specifically timed and handcrafted
  traffic can cause internal errors (related to state transitions) in a WLAN device.");

  script_tag(name:"impact", value:"The flaw lead to improper layer 2 Wi-Fi encryption with a consequent possibility of information
  disclosure over the air for a discrete set of traffic.");

  script_tag(name:"affected", value:"AVM FRITZ!Box devices running AVM FRITZ!OS before version 7.20.

  Common FRITZ!Box models including the 7590, 7580, 7530, 6590 Cable, 6591 Cable and 6660 Cable are
  essentially not affected by the Kr00k vulnerability.

  All products for which the Protected Management Frames (PMF) feature is activated are also not affected.");

  script_tag(name:"vuldetect", value:"Check the AVM FRITZ!OS version.");

  script_tag(name:"solution", value:"Update to AVM FRITZ!OS 7.20 or later.

  A mitigation is to enable the PMF feature in the FRITZ!Box user interface
  under Wireless / Security / Additional Security Settings.");

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

if( model =~ "(7590|7580|7530|6590|6591|6660)" )
  exit( 99 );

patch = "7.20";

if( version_is_less( version:fw_version, test_version:patch ) ) {
  report  = 'Model:              ' + model + '\n';
  report += 'Installed Firmware: ' + fw_version + '\n';
  report += 'Fixed Firmware:     ' + patch;
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

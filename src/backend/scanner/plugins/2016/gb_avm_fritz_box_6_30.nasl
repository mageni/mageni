###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avm_fritz_box_6_30.nasl 11412 2018-09-16 10:21:40Z cfischer $
#
# Multiple AVM FRITZ!Box Remote Code Execution
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/o:avm:fritz%21_os";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105501");
  script_version("$Revision: 11412 $");
  script_name("Multiple AVM FRITZ!Box Remote Code Execution");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-16 12:21:40 +0200 (Sun, 16 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-01-07 18:59:41 +0100 (Thu, 07 Jan 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_avm_fritz_box_detect.nasl");
  script_mandatory_keys("avm/fritz/model", "avm/fritz/firmware_version");

  script_xref(name:"URL", value:"https://www.redteam-pentesting.de/en/advisories/rt-sa-2015-001/-avm-fritz-box-remote-code-execution-via-buffer-overflow");
  script_xref(name:"URL", value:"http://www.heise.de/security/meldung/AVM-Router-Fritzbox-Luecke-erlaubt-Telefonate-auf-fremde-Kosten-3065588.html");
  script_xref(name:"URL", value:"https://avm.de/service/aktuelle-sicherheitshinweise/");

  script_tag(name:"vuldetect", value:"Check the firmware version");

  script_tag(name:"solution", value:"Update the firmware to 6.30 or higher");

  script_tag(name:"summary", value:"Several models of the AVM FRITZ!Box are vulnerable to a stack-based buffer overflow,
  which allows attackers to execute arbitrary code on the device.");

  script_tag(name:"affected", value:"AVM FRITZ!Box 3272/7272, 3370/3390/3490, 7312/7412, 7320/7330 (SL), 736x (SL) and 7490");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! fw_version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );
if( ! model = get_kb_item( "avm/fritz/model" ) ) exit( 0 );

valid_models = make_list( "3272", "7272", "3370", "3390",
                          "3490", "7312", "7412", "7320",
                          "7330", "736[0-9]", "7490" );

foreach m( valid_models ) {
  if( egrep( string:model, pattern:'^' + m ) ) {
    vuln_model = TRUE;
    break;
  }
}

if( ! vuln_model ) exit( 0 );

patch = "6.30";
if( version_is_less( version:fw_version, test_version:patch ) ) {
  report  = 'Model:              ' + model + '\n';
  report += 'Installed Firmware: ' + fw_version + '\n';
  report += 'Fixed Firmware:     ' + patch;
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
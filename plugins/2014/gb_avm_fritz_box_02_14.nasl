###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avm_fritz_box_02_14.nasl 14117 2019-03-12 14:02:42Z cfischer $
#
# Multiple AVM FRITZ!Box Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103911");
  script_version("$Revision: 14117 $");
  script_bugtraq_id(74927, 65520);
  script_cve_id("CVE-2014-9727");
  script_name("Multiple AVM FRITZ!Box Multiple Vulnerabilities");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-02-19 15:07:20 +0100 (Wed, 19 Feb 2014)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_avm_fritz_box_detect.nasl");
  script_mandatory_keys("avm/fritz/model", "avm/fritz/firmware_version");

  script_xref(name:"URL", value:"http://www.avm.de/de/Sicherheit/liste_update.html");
  script_xref(name:"URL", value:"http://www.fritzbox.eu/en/news/2014/security_updates_available.php");
  script_xref(name:"URL", value:"http://www.heise.de/newsticker/meldung/Jetzt-Fritzbox-aktualisieren-Hack-gegen-AVM-Router-auch-ohne-Fernzugang-2115745.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74927");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65520");

  script_tag(name:"vuldetect", value:"Check the firmware version.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references section
  for more information.");

  script_tag(name:"summary", value:"AVM FRITZ!Box is prone to multiple vulnerabilities");

  script_tag(name:"affected", value:"See the list at the linked vendor article.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! fw_version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );
if( ! model = get_kb_item( "avm/fritz/model" ) ) exit( 0 );

fixes = make_array("7570", "4.92",
                   "7490", "6.03",
                   "7390", "6.03",
                   "7362 SL", "6.03",
                   "7360 SL", "6.03",
                   "7360", "6.03",
                   "7330 SL", "6.03",
                   "7330", "6.03",
                   "7320", "6.03",
                   "7312", "6.03",
                   "7272", "6.03",
                   "7270 v2", "5.54",
                   "7270 v3", "5.54",
                   "7270 v1","4.89",
                   "7240", "5.54",
                   "7170 SL", "4.81",
                   "7170", "4.88",
                   "7150", "4.72",
                   "7141", "4.77",
                   "7112", "4.88",
                   "6842 LTE", "6.03",
                   "6840 LTE", "6.03",
                   "6810 LTE", "6.03",
                   "6360 Cable", "6.03",
                   "6340 Cable", "6.03",
                   "6320 Cable", "6.03",
                   "3390", "6.03",
                   "3370", "6.03",
                   "3272", "6.03",
                   "3270", "5.54");

if( ! fixes[model] ) exit( 99 );
patch = fixes[model];

if( version_is_less( version:fw_version, test_version:patch ) ) {
  report  = 'Model:              ' + model + '\n';
  report += 'Installed Firmware: ' + fw_version + '\n';
  report += 'Fixed Firmware:     ' + patch;
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
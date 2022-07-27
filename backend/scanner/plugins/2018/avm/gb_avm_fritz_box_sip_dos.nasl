###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avm_fritz_box_sip_dos.nasl 11417 2018-09-17 05:40:56Z cfischer $
#
# Multiple AVM FRITZ!Box VoIP Remote Denial of Service Vulnerability
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of their respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.108463");
  script_version("$Revision: 11417 $");
  script_cve_id("CVE-2007-0431");
  script_name("Multiple AVM FRITZ!Box VoIP Remote Denial of Service Vulnerability");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 07:40:56 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-09-16 17:38:23 +0200 (Sun, 16 Sep 2018)");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("gb_avm_fritz_box_detect.nasl");
  script_mandatory_keys("avm/fritz/model", "avm/fritz/firmware_version");

  script_xref(name:"URL", value:"https://web.archive.org/web/20160308013152/http://mazzoo.de/blog/2007/01/18");
  script_xref(name:"URL", value:"https://www.securityfocus.com/archive/1/457406/30/0/threaded");

  script_tag(name:"summary", value:"Multiple AVM FRITZ!Box devices are prone to a Denial of Service.");

  script_tag(name:"insight", value:"Sending a zero-length UDP packet to port 5060 (SIP) of a AVM FRITZ!Box will
  crash the VoIP-telephony application. This works from any IP-interface, including the DSL line.");

  script_tag(name:"impact", value:"A remote attacker might be able to crash the VoIP-telephony application.");

  script_tag(name:"vuldetect", value:"Check the AVM FRITZ!OS version.");

  script_tag(name:"solution", value:"Updates are available. Please see the references or the script output
  on the available updates for the matching model.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! fw_version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );
if( ! model = get_kb_item( "avm/fritz/model" ) ) exit( 0 );

# nb: There is no "full" list available on the affected/fixed versions
# and models. The list below was gathered from various online resources.
fixes = make_array("5010", "4.27",
                   "5012", "4.27",
                   "5050", "4.26",
                   "7050", "4.26");

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
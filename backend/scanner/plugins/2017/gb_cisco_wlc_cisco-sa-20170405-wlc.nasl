###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_wlc_cisco-sa-20170405-wlc.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco Wireless LAN Controller 802.11 WME Denial of Service Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/o:cisco:wireless_lan_controller_software";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106727");
  script_cve_id("CVE-2016-9194");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12106 $");

  script_name("Cisco Wireless LAN Controller 802.11 WME Denial of Service Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170405-wlc");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in 802.11 Wireless Multimedia Extensions (WME) action frame
processing in Cisco Wireless LAN Controller (WLC) Software could allow an unauthenticated, adjacent attacker to
cause a denial of service (DoS) condition.");

  script_tag(name:"insight", value:"The vulnerability is due to incomplete input validation of the 802.11 WME
packet header. An attacker could exploit this vulnerability by sending malformed 802.11 WME frames to a targeted
device.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to cause the WLC to reload
unexpectedly.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-07 11:41:27 +0200 (Fri, 07 Apr 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_wlc_version.nasl");
  script_mandatory_keys("cisco_wlc/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe:CPE))
  exit(0);

affected = make_list(
		'5.2.157.0',
		'5.2.169.0',
		'6.0182.0',
		'6.0188.0',
		'6.0196.0',
		'6.0199.4',
		'6.0202.0',
		'7.0116.0',
		'7.0220.0',
		'7.0240.0',
		'7.0250.0',
		'7.0252.0',
		'7.098.0',
		'7.098.218',
		'7.191.0',
		'7.2103.0',
		'7.3.101.0',
		'7.3.103.8',
		'7.3.112',
		'7.4.1.1',
		'7.4.100',
		'7.4.100.60',
		'7.4.110.0',
		'7.4.121.0',
		'7.41.19',
		'7.41.54',
		'7.4140.0',
		'7.5.102.0',
		'7.5.102.11',
		'7.6.1.62',
		'7.6.100.0',
		'7.6.110.0',
		'7.6.120.0',
		'7.6.130.0',
		'8.0.0',
		'8.0.0.30220.385',
		'8.0.100',
		'8.0.115.0',
		'8.0.120.0',
		'8.0.121.0',
		'8.0.72.140',
		'8.1.0',
		'8.1.104.37',
		'8.1.111.0',
		'8.1.122.0',
		'8.1.130.0');

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);


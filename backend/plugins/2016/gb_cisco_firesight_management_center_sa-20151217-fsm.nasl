###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_firesight_management_center_sa-20151217-fsm.nasl 12338 2018-11-13 14:51:17Z asteins $
#
# Cisco FireSIGHT Management Center SSL HTTP Attack Detection Vulnerability
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

CPE = "cpe:/a:cisco:firesight_management_center";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105499");
  script_cve_id("CVE-2015-6427");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_version("$Revision: 12338 $");

  script_name("Cisco FireSIGHT Management Center SSL HTTP Attack Detection Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151217-fsm");

  script_tag(name:"impact", value:"An attacker could exploit this vulnerability by embedding crafted HTTP packets in an encrypted SSL connection that could be flagged as an HTTP attack. An exploit could allow the attacker to bypass HTTP attack rules for SSL connections.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to improper HTTP attack detection of decrypted SSL connections.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"A vulnerability in HTTP attack detection within decrypted SSL traffic of Cisco FireSIGHT Management Center could allow an unauthenticated, remote attacker to bypass HTTP attack detection. The traffic is SSL and the application is configured to decrypt the SSL connection and detect HTTP-based attacks that are associated with Snort intrusion detection rules.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-01-06 13:43:05 +0100 (Wed, 06 Jan 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_firesight_management_center_version.nasl",
                     "gb_cisco_firesight_management_center_http_detect.nasl");
  script_mandatory_keys("cisco_firesight_management_center/version");

  exit(0);
}

include("host_details.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

affected = make_list(
                '5.3.0',
                '5.3.0.1',
                '5.3.0.2',
                '5.3.1.1',
                '5.3.1.2',
                '5.3.1.3',
                '5.3.1',
                '5.3.1.5',
                '5.3.1.4',
                '5.3.1.7',
                '5.4.0',
                '5.4.1',
                '5.4.1.2',
                '5.4.0.1',
                '5.4.0.4',
                '5.4.1.3',
                '5.4.1.4',
                '6.0.0',
                '6.0.0.1',
                '6.0.1' );

foreach af (affected) {
  if (version == af) {
    report = 'Installed version: ' + version + '\n' +
             'Fixed version:     No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.';

    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );


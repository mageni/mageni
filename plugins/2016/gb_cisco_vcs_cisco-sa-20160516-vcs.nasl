###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_vcs_cisco-sa-20160516-vcs.nasl 12431 2018-11-20 09:21:00Z asteins $
#
# Cisco Video Communication Server Session Initiation Protocol Packet Processing Denial of Service Vulnerability
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

CPE = "cpe:/a:cisco:telepresence_video_communication_server_software";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105723");
  script_cve_id("CVE-2016-1400");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("$Revision: 12431 $");

  script_name("Cisco Video Communication Server Session Initiation Protocol Packet Processing Denial of Service Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160516-vcs");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to a malformed SIP header message. An attacker could exploit this vulnerability by manipulating the SIP URI. An exploit could allow the attacker to cause a disruption of service to the application.");

  script_tag(name:"solution", value:"Update to version X8.7.2 or higher.");
  script_tag(name:"summary", value:"A vulnerability in the Session Initiation Protocol (SIP) implementation of the Cisco Video Communications Server (VCS) could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition.");
  script_tag(name:"affected", value:"Cisco TelePresence VCS X8.x releases prior to X8.7.2 are vulnerable.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"$Date: 2018-11-20 10:21:00 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-05-17 15:13:01 +0200 (Tue, 17 May 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_vcs_detect.nasl", "gb_cisco_vcs_ssh_detect.nasl");
  script_mandatory_keys("cisco_vcs/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

if( version =~ "^8\." )
{
  if( version_is_less( version:version, test_version:"8.7.2" ) )
  {
    report = report_fixed_ver(  installed_version:version, fixed_version:"X8.7.2" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

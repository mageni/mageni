###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_vcs_CSCuv11969.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco TelePresence Video Communication Server Expressway File Modification Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105403");
  script_cve_id("CVE-2015-6318");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 12106 $");

  script_name("Cisco TelePresence Video Communication Server Expressway File Modification Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151007-vcs");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability is due to insufficient protection of files. An attacker could exploit this vulnerability by creating a malicious symbolic link to a location not otherwise accessible to the attacker. An exploit could allow the attacker to insert unauthorized content in the linked-to file.");
  script_tag(name:"solution", value:"Updates are available");
  script_tag(name:"summary", value:"A vulnerability in the symbolic link operation of the Cisco TelePresence Video Communication Server (VCS) Expressway could allow an authenticated, local attacker to perform a symbolic link attack on the affected system.");
  script_tag(name:"affected", value:"Cisco TelePresence Video Communication Server version X8.5.2 is vulnerable.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-10-14 15:11:26 +0200 (Wed, 14 Oct 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_vcs_detect.nasl", "gb_cisco_vcs_ssh_detect.nasl");
  script_mandatory_keys("cisco_vcs/installed");

  exit(0);
}

include("host_details.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

if( version =~ "^8\.5\.2($|[^0-9])" )
{
  report = 'Installed version: ' + version + '\n' +
           'Fixed version:     Ask the vendor\n';
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );


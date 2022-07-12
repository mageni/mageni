###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_vcs_76352.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco TelePresence Video Communication Server Expressway Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.105333");
  script_bugtraq_id(76352);
  script_cve_id("CVE-2015-4315");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_version("$Revision: 12106 $");

  script_name("Cisco TelePresence Video Communication Server Expressway Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76352");
  script_xref(name:"URL", value:"https://tools.cisco.com/bugsearch/bug/CSCuv31853");

  script_tag(name:"impact", value:"An attacker can exploit this issue to cause a denial of service condition or read arbitrary files on an affected system.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability is due to insufficient validation of declared document type definitions (DTD) stored externally. An attacker could exploit this
vulnerability by supplying a specially crafted XML file to the targeted system. An exploit could allow the attacker to launch a denial of service or read arbitrary files.

This issue is being tracked by Cisco bug ID CSCuv31853");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"summary", value:"Cisco TelePresence Video Communication Server Expressway is prone to a denial-of-service vulnerability.");
  script_tag(name:"affected", value:"Cisco TelePresence Video Communication Server Expressway X8.5.3");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-08-27 15:43:02 +0200 (Thu, 27 Aug 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_vcs_detect.nasl", "gb_cisco_vcs_ssh_detect.nasl");
  script_mandatory_keys("cisco_vcs/installed");

  exit(0);
}

include("host_details.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

if( version =~ "^8\.5\.3($|[^0-9])" )
{
  report = 'Installed version: ' + version + '\n' +
           'Fixed version:     Ask the vendor\n';
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );


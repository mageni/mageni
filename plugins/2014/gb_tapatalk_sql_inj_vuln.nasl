###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tapatalk_sql_inj_vuln.nasl 12083 2018-10-25 09:48:10Z cfischer $
#
# Tapatalk Blind SQL Injection Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:tapatalk:tapatalk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105933");
  script_cve_id("CVE-2014-2023");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 12083 $");

  script_name("Tapatalk Blind SQL Injection Vulnerability");

  script_xref(name:"URL", value:"https://github.com/tintinweb/pub/tree/master/pocs/cve-2014-2023");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70418/");

  script_tag(name:"summary", value:"Tapatalk is prone to a SQL Injection Vulnerability");

  script_tag(name:"impact", value:"A successful exploit may allow an unauthenticated attacker to
  compromise the application, access or modify data, or exploit latent vulnerabilities in the underlying
  database.");

  script_tag(name:"insight", value:"Tapatalk for vBulletin 4.x does not properly sanitize some xmlrpc
  calls for unsubscribe_topic, unsubscribe_forum allowing unauthenticated users to inject arbitrary SQL commands.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Upgrade to Tapatalk vBulletin 4.x plugin series 5.2.2 or higher.");

  script_tag(name:"affected", value:"Tapatalk for vBulletin 4.x plugin series 5.2.1 and below.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 11:48:10 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-11-27 14:20:39 +0700 (Thu, 27 Nov 2014)");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("sw_tapatalk_detect.nasl");
  script_mandatory_keys("tapatalk/vbulletin/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if (version_is_less(version:vers, test_version:"5.2.2")) {
  report = 'Installed version: ' + vers + '\n' +
           'Fixed version:     ' + "5.2.2" + '\n';
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_activemq_xss_win.nasl 12419 2018-11-19 13:45:13Z cfischer $
#
# Apache Active MQ 5.14.1 XSS Vulnerability (Windows)
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113082");
  script_version("$Revision: 12419 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-19 14:45:13 +0100 (Mon, 19 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-01-12 13:07:08 +0100 (Fri, 12 Jan 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2016-6810");

  script_name("Apache Active MQ 5.14.1 XSS Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_activemq_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ActiveMQ/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache Active MQ 5.x before 5.14.1 is prone to an authenticated XSS vulnerability.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw exists due to improper user data output validation.");
  script_tag(name:"affected", value:"Apache Active MQ 5.x before 5.14.1.");
  script_tag(name:"solution", value:"Update to Apache Active MQ 5.14.2 or above.");

  script_xref(name:"URL", value:"http://activemq.apache.org/security-advisories.data/CVE-2016-6810-announcement.txt");
  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/924a3a27fad192d711436421e02977ff90d9fc0f298e1efe6757cfbc@%3Cusers.activemq.apache.org%3E");

  exit(0);
}

CPE = "cpe:/a:apache:activemq";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! version = get_app_version( cpe: CPE, nofork: TRUE ) ) exit( 0 );

if( version_in_range( version: version, test_version: "5.0.0", test_version2: "5.14.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.14.2" );
  security_message( port: 0, data: report );
  exit( 0 );
}

exit( 99 );

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_activemq_mitm_vuln_win.nasl 12447 2018-11-21 04:17:12Z ckuersteiner $
#
# Apache Active MQ 5.0.0 - 5.15.5 Missing TLS Hostname Verification (Windows)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.112387");
  script_version("$Revision: 12447 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 05:17:12 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-09-20 14:15:00 +0200 (Thu, 20 Sep 2018)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-11775");
  script_bugtraq_id(105335);

  script_name("Apache Active MQ 5.0.0 - 5.15.5 Missing TLS Hostname Verification (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_activemq_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ActiveMQ/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache Active MQ is missing its TLS hostname verification.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"TLS hostname verification when using the Apache ActiveMQ Client was missing
which could make the client vulnerable to a MITM attack between a Java application using the ActiveMQ client and the ActiveMQ server.
This is now enabled by default.");
  script_tag(name:"affected", value:"Apache Active MQ 5.0.0 up to and including 5.15.5.");
  script_tag(name:"solution", value:"Update to Apache Active MQ 5.15.6 or later.");

  script_xref(name:"URL", value:"http://activemq.apache.org/security-advisories.data/CVE-2018-11775-announcement.txt");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

CPE = "cpe:/a:apache:activemq";

if( ! version = get_app_version( cpe: CPE, nofork: TRUE ) ) exit( 0 );

if( version_in_range( version: version, test_version: "5.0.0", test_version2: "5.15.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.15.6" );
  security_message( port: 0, data: report );
  exit( 0 );
}

exit( 99 );

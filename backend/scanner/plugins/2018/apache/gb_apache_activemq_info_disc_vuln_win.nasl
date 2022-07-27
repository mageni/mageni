###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_activemq_info_disc_vuln_win.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# Apache Active MQ 5.14.0 - 5.15.2 Information Disclosure Vulnerability (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.112225");
  script_version("$Revision: 12116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-02-15 14:55:00 +0100 (Thu, 15 Feb 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-15709");

  script_name("Apache Active MQ 5.14.0 - 5.15.2 Information Disclosure Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_activemq_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ActiveMQ/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache Active MQ is prone to an information disclosure vulnerability.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"When using the OpenWire protocol it was found that certain system
  details (such as the OS and kernel version) are exposed as plain text.");
  script_tag(name:"affected", value:"Apache Active MQ 5.14.0 up to and including 5.15.2.");
  script_tag(name:"solution", value:"Update to Apache Active MQ 5.15.3 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/2b6f04a552c6ec2de6563c2df3bba813f0fe9c7e22cce27b7829db89@%3Cdev.activemq.apache.org%3E");

  exit(0);
}

CPE = "cpe:/a:apache:activemq";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! version = get_app_version( cpe: CPE, nofork: TRUE ) ) exit( 0 );

if( version_in_range( version: version, test_version: "5.14.0", test_version2: "5.15.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.15.3" );
  security_message( port: 0, data: report );
  exit( 0 );
}

exit( 99 );

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_activemq_dos_vuln2_lin.nasl 11983 2018-10-19 10:04:45Z mmartin $
#
# Apache ActiveMQ 'CVE-2014-3576' Denial of Service Vulnerability (Linux)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:apache:activemq";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108287");
  script_version("$Revision: 11983 $");
  script_cve_id("CVE-2014-3576");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-07 10:54:29 +0100 (Tue, 07 Nov 2017)");
  script_name("Apache ActiveMQ 'CVE-2014-3576' Denial of Service Vulnerability (Linux)");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_apache_activemq_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ActiveMQ/installed", "Host/runs_unixoide");

  script_xref(name:"URL", value:"http://activemq.apache.org/security-advisories.html");

  script_tag(name:"summary", value:"This host is running Apache ActiveMQ and is prone to
  a Denial of Service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows remote
  attackers to cause a Denial of Service via a shutdown command.");

  script_tag(name:"affected", value:"Apache ActiveMQ version before 5.11.0.");

  script_tag(name:"solution", value:"Update to Apache ActiveMQ version 5.11.0, or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! vers = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"5.11.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.11.0" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
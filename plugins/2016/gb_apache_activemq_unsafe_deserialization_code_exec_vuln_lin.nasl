###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_activemq_unsafe_deserialization_code_exec_vuln_lin.nasl 12431 2018-11-20 09:21:00Z asteins $
#
# Apache ActiveMQ Unsafe deserialization Code Execution Vulnerability (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.809062");
  script_version("$Revision: 12431 $");
  script_cve_id("CVE-2015-5254");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-20 10:21:00 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-10-04 19:50:32 +0530 (Tue, 04 Oct 2016)");
  script_name("Apache ActiveMQ Unsafe deserialization Code Execution Vulnerability (Linux)");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_activemq_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8161, "Services/activemq_jms", 61616);
  script_mandatory_keys("ActiveMQ/installed", "Host/runs_unixoide");

  script_xref(name:"URL", value:"http://activemq.apache.org/security-advisories.data/CVE-2015-5254-announcement.txt");

  script_tag(name:"summary", value:"This host is running Apache ActiveMQ and is
  prone to an arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to not restricting the
  classes that can be serialized in the broker.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code via a crafted serialized Java Message
  Service (JMS) ObjectMessage object.");

  script_tag(name:"affected", value:"Apache ActiveMQ Version 5.0 through 5.12.1
  on Linux");

  script_tag(name:"solution", value:"Upgrade to Apache ActiveMQ Version
  5.13.0 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! appVer = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

if( version_in_range( version:appVer, test_version:"5.0.0", test_version2:"5.12.1" ) ) {
  report = report_fixed_ver( installed_version:appVer, fixed_version:"5.13.0" );
  security_message( data:report, port:0 );
  exit( 0 );
}

exit( 99 );
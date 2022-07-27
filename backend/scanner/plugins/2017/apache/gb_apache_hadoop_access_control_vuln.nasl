###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_hadoop_access_control_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Apache Hadoop Insufficient Access Control Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:apache:hadoop";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140516");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-21 11:32:39 +0700 (Tue, 21 Nov 2017)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-3166");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Hadoop Insufficient Access Control Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_hadoop_detect.nasl");
  script_mandatory_keys("Apache/Hadoop/Installed");

  script_tag(name:"summary", value:"Apache Hadoop is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In a cluster where the YARN user has been granted access to all HDFS
encryption keys, if a file in an encryption zone with access permissions that make it world readable is localized
via YARN's localization mechanism, e.g. via the MapReduce distributed cache, that file will be stored in a
world-readable location and shared freely with any application that requests to localize that file, no matter who
the application owner is or whether that user should be allowed to access files from the target encryption zone.");

  script_tag(name:"impact", value:"Users may gain access to files that should be protected by HDFS transparent
encryption if those files have world readable access permissions and are localized through YARN's localization
mechanism in a cluster where YARN has been granted access to all HDFS encryption keys.");

  script_tag(name:"affected", value:"Apache Hadoop version 2.6.1, 2.7.x and 3.0.0-alpha.");

  script_tag(name:"solution", value:"Update to version 2.7.4, 3.0.0-alpha4 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/2e16689b44bdd1976b6368c143a4017fc7159d1f2d02a5d54fe9310f@%3Cgeneral.hadoop.apache.org%3E");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2.7.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.7.4");
  security_message(port: port, data: report);
  exit(0);
}



exit(0);

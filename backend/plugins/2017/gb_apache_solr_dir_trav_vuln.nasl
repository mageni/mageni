###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_solr_dir_trav_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Apache Solr Path Traversal Vulnerability
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

CPE = "cpe:/a:apache:solr";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140341");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-31 15:14:14 +0700 (Thu, 31 Aug 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2017-3163");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Solr Inter-Node Communication Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_apache_solr_detect.nasl");
  script_mandatory_keys("Apache/Solr/Installed");

  script_tag(name:"summary", value:"When using the Index Replication feature, Apache Solr nodes can pull index
files from a master/leader node using an HTTP API which accepts a file name. However, Solr did not validate the
file name, hence it was possible to craft a special request involving path traversal, leaving any file readable
to the Solr server process exposed. Solr servers protected and restricted by firewall rules and/or authentication
would not be at risk since only trusted clients and users would gain direct HTTP access.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache Solr before 5.5.4 and 6.x.");

  script_tag(name:"solution", value:"Upgrade to version 5.5.4, 6.4.1 or later.");

  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/SOLR-10031");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "5.5.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.4");
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^6\.") {
  if (version_is_less(version: version, test_version: "6.4.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.4.1");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);

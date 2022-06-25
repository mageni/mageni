###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_solr_pki_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Apache Solr Inter-Node Communication Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.106934");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-10 14:38:21 +0700 (Mon, 10 Jul 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2017-7660");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Solr Inter-Node Communication Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_apache_solr_detect.nasl");
  script_mandatory_keys("Apache/Solr/Installed");

  script_tag(name:"summary", value:"Solr uses a PKI based mechanism to secure inter-node communication when
security is enabled. It is possible to create a specially crafted node name that does not exist as part of the
cluster and point it to a malicious node. This can trick the nodes in cluster to believe that the malicious node
is a member of the cluster. So, if Solr users have enabled BasicAuth authentication mechanism using the
BasicAuthPlugin or if the user has implemented a custom Authentication plugin, which does not implement either
'HttpClientInterceptorPlugin' or 'HttpClientBuilderPlugin', his/her servers are vulnerable to this attack. Users
who only use SSL without basic authentication or those who use Kerberos are not affected.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache Solr 5.x and 6.x");

  script_tag(name:"solution", value:"Upgrade to version 5.5.5, 6.6.0 or later.");

  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/SOLR-10624");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "5.3.0", test_version2: "5.5.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.5");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "6.0.0", test_version2: "6.5.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.6.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

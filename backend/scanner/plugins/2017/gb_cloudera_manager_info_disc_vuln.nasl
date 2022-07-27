###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cloudera_manager_info_disc_vuln.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# Cloudera Manager Configuration Download Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:cloudera:cloudera_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106786");
  script_version("$Revision: 11874 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-25 08:10:42 +0200 (Tue, 25 Apr 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Cloudera Manager Configuration Download Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_cloudera_manager_detect.nasl");
  script_mandatory_keys("cloudera_manager/installed");

  script_tag(name:"summary", value:"Cloudera Manager is prone to a information disclosure vulnerability where
a unauthenticated attacker may download module configurations.");

  script_tag(name:"vuldetect", value:"Tries to download a module configuration.");

  script_tag(name:"insight", value:"Cloudera Manager allows to download module configurations without
authentication by iterating on the module index.");

  script_tag(name:"solution", value:"The vulnerability can be mitigated by requiring authentication by
setting 'client_config_auth'.");

  script_xref(name:"URL", value:"https://github.com/wavestone-cdt/hadoop-attack-library/tree/master/Third-party%20modules%20vulnerabilities/Cloudera%20Manager/Unauthenticated%20configuration%20download");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

# max try until module index 20
for (i=1; i<=20; i++) {
  url = '/cmf/services/' + i + '/client-config';

  if (http_vuln_check(port: port, url: url, pattern: "Content-Type: application/zip", check_header: TRUE,
                      extra_check: "Content-disposition: attachment")) {
    report = report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);

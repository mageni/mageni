# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107652");
  script_version("2019-05-24T13:14:04+0000");
  script_tag(name:"last_modification", value:"2019-05-24 13:14:04 +0000 (Fri, 24 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-06 14:43:56 +0200 (Mon, 06 May 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache Tomcat Detection (Consolidation)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_apache_tomcat_detect_win.nasl", "gb_apache_tomcat_detect.nasl");
  script_mandatory_keys("apache/tomcat/detected");

  script_tag(name:"summary", value:"Reports on findings if an installation of
  Apache Tomcat has been found on the target system.");

  script_xref(name:"URL", value:"http://tomcat.apache.org/");

  exit(0);
}

include("host_details.inc");
include("cpe.inc");

if( ! get_kb_item( "apache/tomcat/detected" ) )
  exit( 0 );

report = "";

if( count_list = get_kb_list( "apache/tomcat/smb/count" ) ) {

  count_list = sort( count_list );

  foreach install( count_list ) {

    version = get_kb_item( "apache/tomcat/smb/" + install + "/version" );
    if( ! version )
      continue;

    concl = get_kb_item( "apache/tomcat/smb/" + install + "/concluded" );
    insloc = get_kb_item( "apache/tomcat/smb/" + install + "/location" );
    CPE = build_cpe( value:version, exp:"([0-9.]+)", base:"cpe:/a:apache:tomcat:" );
    if( ! CPE )
      CPE = "cpe:/a:apache:tomcat";

    register_product( cpe:CPE, location:insloc, port:0, service:"smb-login" );

    if( report )
      report += '\n\n';

    report += build_detection_report( app:"Apache Tomcat (SMB)", version:version, install:insloc, cpe:CPE, concluded:concl );
  }
}

if( http_ports = get_kb_list( "apache/tomcat/http/port" ) ) {

  http_ports = sort( http_ports );

  foreach port( http_ports ) {

    version = get_kb_item( "apache/tomcat/http/" + port + "/version" );
    if( ! version )
      continue;

    concl = get_kb_item( "apache/tomcat/http/" + port + "/concluded" );
    conclurl = get_kb_item( "apache/tomcat/http/" + port + "/concludedUrl" );
    loc = get_kb_item( "apache/tomcat/http/" + port + "/location" );
    CPE = build_cpe( value:version, exp:"([0-9.]+)", base:"cpe:/a:apache:tomcat:" );
    if( ! CPE )
      CPE = "cpe:/a:apache:tomcat";

    register_product( cpe:CPE, location:loc, port:port, service:"www" );

    if( report )
      report += '\n\n';

    report += build_detection_report( app:"Apache Tomcat (HTTP)", version:version, install:loc + " on port " + port + "/tcp", cpe:CPE, concluded:concl, concludedUrl:conclurl );
  }
}

log_message( port:0, data:report );

exit( 0 );
# Copyright (C) 2016 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

CPE = "cpe:/a:meteocontrol:weblog";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107003");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2016-2296");
  script_version("2021-09-17T12:31:03+0000");
  script_tag(name:"last_modification", value:"2021-09-20 10:59:32 +0000 (Mon, 20 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-07 01:29:00 +0000 (Thu, 07 Sep 2017)");
  script_tag(name:"creation_date", value:"2016-05-20 10:42:39 +0100 (Fri, 20 May 2016)");
  script_name("Meteocontrol WEB'log Admin Password Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_Meteocontrol_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("meteocontrol/weblog/installed");

  script_xref(name:"URL", value:"http://ipositivesecurity.blogspot.in/2016/05/ics-meteocontrol-weblog-security.html");
  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-16-133-01");

  script_tag(name:"impact", value:"Sensitive information can be accessed, and admin login pages are
  accessible without being authenticated.");

  script_tag(name:"affected", value:"All Meteocontrol's WEB'log versions / flavors have the same
  underlying design and are vulnerable.");

  script_tag(name:"summary", value:"Meteocontrol WEB'log is vulnerable to an admin password
  disclosure.");

  script_tag(name:"insight", value:"All Meteocontrol WEB'log application functionality, and
  configuration pages, including those accessible after administrative login, can be accessed
  without any authentication.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"qod_type", value:"exploit");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir  = get_app_location( port:port, cpe:CPE ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/html/en/confAccessProt.html";
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf =~ "^HTTP/1\.[01] 200" && ( buf =~ "szWebAdminPassword" || buf =~ "/Admin Monitoring/" ) ) {

  pass = eregmatch( string:buf, pattern:'"szWebAdminPassword" value="([^"]+)"', icase:TRUE );
  if( pass[1] ) {
    report  = http_report_vuln_url( port:port, url:url ) + '\n';
    report += "The following password is disclosed: " + pass[1];
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
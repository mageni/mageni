###############################################################################
# OpenVAS Vulnerability Test
# $Id: redaxscript_34476.nasl 13902 2019-02-27 10:31:50Z cfischer $
#
# Redaxscript 'language' Parameter Local File Include Vulnerability
#
# Authors
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:redaxscript:redaxscript";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100122");
  script_version("$Revision: 13902 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-27 11:31:50 +0100 (Wed, 27 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-04-12 20:09:50 +0200 (Sun, 12 Apr 2009)");
  script_bugtraq_id(34476);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Redaxscript 'language' Parameter Local File Include Vulnerability");
  script_category(ACT_MIXED_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("redaxscript_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("redaxscript/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34476");

  script_tag(name:"summary", value:"Redaxscript is prone to a local file-include vulnerability because
  it fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to view and execute
  arbitrary local files in the context of the webserver process. This may aid in further attacks.");

  script_tag(name:"affected", value:"Redaxscript 0.2.0 is vulnerable. Other versions may also be
  affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("version_func.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:FALSE ) )
  exit( 0 );

vers = infos['version'];
dir = infos['location'];

if(vers && vers != "unknown" ) {
  if(version_is_equal( version:vers, test_version:"0.2.0" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"None", install_path:dir );
    security_message( port:port, data:report );
    exit( 0 );
  }
  exit( 99 );
} else {

  if( ! dir )
    exit( 0 );

  if( dir == "/" )
    dir = "";

  # No version found, try to exploit.
  files = traversal_files();
  foreach pattern( keys( files ) ) {

    file = files[pattern];
    url = string(dir, "/index.php?language=../../../../../../../../", file, "%00");

    if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
      report = report_vuln_url( url:url, port:port );
      security_message( port:port, data:url );
      exit( 0 );
    }
  }
}

exit( 99 );
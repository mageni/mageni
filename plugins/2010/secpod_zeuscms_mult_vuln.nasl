##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_zeuscms_mult_vuln.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# ZeusCMS Multiple Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
################################i###############################################

CPE = "cpe:/a:zeuscms:zeuscms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902020");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-02-26 10:13:54 +0100 (Fri, 26 Feb 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_bugtraq_id(38237);
  script_cve_id("CVE-2010-0680", "CVE-2010-0681");
  script_name("ZeusCMS Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_zeuscms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("zeuscms/installed");

  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/391047.php");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/11437");

  script_tag(name:"insight", value:"- Error in 'index.php', which allows remote attackers to include and execute
    arbitrary local files via directory traversal sequences in the page
    parameter.

  - Sensitive information under the web root is stored, which allows remote
    attackers to issue a direct request to 'admin/backup.sql' and fetch
    sensitive information.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running ZeusCMS and is prone to multiple
  vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to obtain potentially sensitive
  information and execute arbitrary local scripts in the context of the
  webserver process.");

  script_tag(name:"affected", value:"ZeusCMS version 0.2");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:FALSE ) ) exit( 0 );

vers = infos['version'];
dir = infos['location'];
if( dir == "/" ) dir = "";

url = dir + "/admin/backup.sql";

sndReq = http_get( item:url , port:port );
rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

if( "ZeusCMS" >< rcvRes && "CREATE TABLE" >< rcvRes && "INSERT INTO" >< rcvRes ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

if( ! isnull( vers ) ) {
  if( version_is_equal( version:vers, test_version:"0.2" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"None available" );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
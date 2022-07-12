###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_eclime_mult_sql_inj_n_xss_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Eclime Multiple SQL Injection and Cross-site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801990");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-10-20 08:43:23 +0200 (Thu, 20 Oct 2011)");
  script_cve_id("CVE-2010-4851", "CVE-2010-4852");
  script_bugtraq_id(45124);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Eclime Multiple SQL Injection and Cross-site Scripting Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15644/");
  script_xref(name:"URL", value:"http://securityreason.com/securityalert/8399");
  script_xref(name:"URL", value:"https://www.htbridge.ch/advisory/sql_injection_in_eclime.html");
  script_xref(name:"URL", value:"https://www.htbridge.ch/advisory/sql_injection_in_eclime_1.html");
  script_xref(name:"URL", value:"https://www.htbridge.ch/advisory/sql_injection_in_eclime_2.html");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary
  script code or to compromise the application, access or modify data, or exploit
  latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"Eclime version 1.1.2b");

  script_tag(name:"insight", value:"Multiple flaws are due to an,

  - Input passed via the parameters 'ref', ' poll_id' in 'index.php' and the
  parameter 'country' in 'create_account.php' script is not properly
  sanitised before being used in SQL queries.

  - Input passed via the parameter 'login' in 'login.php' script is not
  sanitized allowing the attacker to execute HTML code.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running Eclime and is prone to multiple cross site
  scripting and SQL injection vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/eclime", "/eclime/catalog", "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  res = http_get_cache( item:dir + "/index.php", port:port );

  if( ">eclime</" >< res && '> e-commerce software.<' >< res ) {

    url = dir + '/login.php?login=fail&reason=<script>alert(document.cookie);</script>';
    if( http_vuln_check( port:port, url:url, pattern:"<script>alert\(document\.cookie\);</script>", check_header:TRUE ) ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }

    url = dir + "/?ref='";
    if( http_vuln_check( port:port, url:url, pattern:"You have an error in your SQL syntax;" ) ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
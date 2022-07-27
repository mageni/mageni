##############################################################################
# OpenVAS Vulnerability Test
# $Id: ilohamail_conf_files_readable.nasl 13238 2019-01-23 11:14:26Z cfischer $
#
# IlohaMail Readable Configuration Files
#
# Authors:
# George A. Theall, <theall@tifaware.com>.
#
# Copyright:
# Copyright (C) 2005 George A. Theall
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

CPE = "cpe:/a:ilohamail:ilohamail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16142");
  script_version("$Revision: 13238 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-23 12:14:26 +0100 (Wed, 23 Jan 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_bugtraq_id(12252);
  script_name("IlohaMail Readable Configuration Files");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 George A. Theall");
  script_family("Remote file access");
  script_dependencies("ilohamail_detect.nasl");
  script_mandatory_keys("ilohamail/detected");

  script_tag(name:"solution", value:"Upgrade to IlohaMail version 0.8.14-rc2 or later or
  reinstall following the 'Proper Installation' instructions in the INSTALL document.");

  script_tag(name:"summary", value:"The target is running at least one instance of IlohaMail that allows
  anyone to retrieve its configuration files over the web. These files may contain sensitive information.
  For example, conf/conf.inc may hold a username / password used for SMTP authentication.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir  = get_app_location( cpe:CPE, port:port ) ) exit( 0 );
if( dir == "/" ) dir = "";

# If this was a quick & dirty install, try to grab a config file.
if( dir =~ "/source$" ) {

  dir = ereg_replace( string:dir, pattern:"/source$", replace:"/conf" );
  # nb: conf.inc appears first in 0.7.3; mysqlrc.inc was used as far back as 0.7.0.
  foreach config( make_list("conf.inc", "mysqlrc.inc" ) ) {
    url = dir + "/" + config;
    req = http_get( item:url, port:port );
    res = http_keepalive_send_recv( port:port, data:req );
    if( ! res ) continue;

    # Does it look like PHP code with variable definitions?
    if( egrep( string:res, pattern:"<\?php") && egrep( string:res, pattern:"\$[A-Za-z_]+ *= *.+;" ) ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
###############################################################################
# OpenVAS Vulnerability Test
# $Id: phpinfo.nasl 11992 2018-10-19 13:42:04Z cfischer $
#
# phpinfo() output Reporting
#
# Authors:
# Randy Matz <rmatz@ctusa.net>
#
# Copyright:
# Copyright (C) 2003 Randy Matz
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.11229");
  script_version("$Revision: 11992 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 15:42:04 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("phpinfo() output Reporting");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Randy Matz");
  script_family("Web application abuses");
  script_dependencies("gb_phpinfo_output_detect.nasl");
  script_mandatory_keys("php/phpinfo/detected");

  script_tag(name:"solution", value:"Delete the listed files or restrict access to them.");

  script_tag(name:"summary", value:"Many PHP installation tutorials instruct the user to create
  a file called phpinfo.php or similar containing the phpinfo() statement. Such a file is often
  left back in the webserver directory.");

  script_tag(name:"impact", value:"Some of the information that can be gathered from this file includes:

  The username of the user running the PHP process, if it is a sudo user, the IP address of the host, the web server
  version, the system version (Unix, Linux, Windows, ...), and the root directory of the web server.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("http_func.inc");
include("misc_func.inc");

report = 'The following files are calling the function phpinfo() which disclose potentially sensitive information:\n';

port = get_http_port( default:80 );
# nb: Don't use can_host_php() here as this NVT is reporting PHP as well
# and can_host_php() could fail if no PHP was detected before...

host = http_host_name( dont_add_port:TRUE );

if( ! get_kb_item( "php/phpinfo/" + host + "/" + port + "/detected" ) ) exit( 99 );

url_list = get_kb_list( "www/" + host + "/" + port + "/content/phpinfo_script/reporting" );
if( ! is_array( url_list ) ) exit( 99 );

# nb: Sort to not report differences on delta reports just the order is different.
url_list = sort( url_list );

foreach url( url_list ) {
  report += '\n' + url;
}

security_message( port:port, data:report );
exit( 0 );
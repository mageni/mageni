###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avm_fritz_box_ftp_default_pass.nasl 13497 2019-02-06 10:45:54Z cfischer $
#
# AVM FRITZ!Box Default Password (FTP)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/o:avm:fritz%21_os";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108043");
  script_version("$Revision: 13497 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 11:45:54 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-01-11 11:00:00 +0100 (Wed, 11 Jan 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("AVM FRITZ!Box Default Password (FTP)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("gb_avm_fritz_box_detect.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("avm_fritz_box/ftp/detected");

  script_tag(name:"summary", value:"This script detects if the device has a default password set.");

  script_tag(name:"vuldetect", value:"Check if it is possible to login with a default password.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
  access to sensitive information.");

  script_tag(name:"solution", value:"Set change the identified default password.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("ftp_func.inc");
include("host_details.inc");

creds = make_list( "1234",
                   "0000",
                   "admin",
                   "password",
                   "passwort" );

if( ! port = get_app_port( cpe:CPE, service:"ftp" ) ) exit( 0 );
get_app_location( cpe:CPE, port:port, nofork:TRUE ); # To have a reference to the Detection-NVT

if( get_kb_item( "ftp/" + port + "/anonymous" ) ) exit( 0 );

banner = get_ftp_banner( port:port );

if( "FRITZ!Box" >!< banner && "FTP server ready." >!< banner ) exit( 0 );

foreach cred ( creds ) {

  soc = open_sock_tcp( port );
  if( ! soc ) exit( 0 );

  if( ftp_authenticate( socket:soc, user:"ftpuser", pass:cred ) ) {
    report = "It was possible to login using the following default credentials: 'ftpuser:" + cred + "'.";
    security_message( port:port, data:report );
    ftp_close( socket:soc );
    exit( 0 );
  }
  ftp_close( socket:soc );
}

exit( 99 );
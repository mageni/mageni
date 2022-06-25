###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hpkp_low_max_age.nasl 7395 2017-10-10 14:12:44Z cfischer $
#
# SSL/TLS: Check for `max-age` Attribute in HPKP Header
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.108250");
  script_version("$Revision: 7395 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-10 16:12:44 +0200 (Tue, 10 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-10-10 13:07:41 +0200 (Tue, 10 Oct 2017)");
  script_name('SSL/TLS: Check for `max-age` Attribute in HPKP Header');
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_hpkp_detect.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("hpkp/available/port");
  script_add_preference(name:"Minimum max-age value (in seconds)", type:"entry", value:"5184000");

  script_xref(name:"URL", value:"https://www.owasp.org/index.php/OWASP_Secure_Headers_Project");
  script_xref(name:"URL", value:"https://www.owasp.org/index.php/OWASP_Secure_Headers_Project#hpkp");
  script_xref(name:"URL", value:"https://tools.ietf.org/html/rfc7469");
  script_xref(name:"URL", value:"https://securityheaders.io/");

  script_tag(name:"summary", value:"The remote HTTPS Server is using a too low value within the 'max-age' attribute in the HPKP header.");

  script_tag(name:"solution", value:"The recommended value should aim towards 60 days (5184000 seconds) but heavily depends on your deployment scenario.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

max_age_check = int( script_get_preference( "Minimum max-age value (in seconds)" ) );
if( max_age_check <= 0 ) max_age_check = 5184000;

if( ! port = get_kb_item( "hpkp/available/port" ) ) exit( 0 );
if( isnull( current_max_age = get_kb_item( "hpkp/max_age/" + port ) ) ) exit( 0 );

# The return of the above get_kb_item is "data"
current_max_age = int( current_max_age );
if( current_max_age <= 0 ) exit( 0 ); # Something went wrong...

if( current_max_age < max_age_check ) {
  banner = get_kb_item( "hpkp/" + port + "/banner" );
  report = 'The remote HTTPS Server is using a value of "' +  current_max_age + '" within the "max-age" attribute in the HPKP header. ';
  report += 'This value is below the configured / minimal recommended value of "' + max_age_check + '".\n\nHPKP Header:\n\n' + banner;
  log_message( port:port, data:report );
}

exit( 0 );

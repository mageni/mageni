# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117537");
  script_version("2021-07-07T08:14:44+0000");
  script_tag(name:"last_modification", value:"2021-07-07 08:14:44 +0000 (Wed, 07 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-06 12:14:06 +0000 (Tue, 06 Jul 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Apache HTTP Server 'mod_perl' /perl-status accessible (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://perl.apache.org/docs/2.0/api/Apache2/Status.html");

  script_tag(name:"summary", value:"Requesting the URI /perl-status provides a comprehensive
  overview of the server configuration.");

  script_tag(name:"insight", value:"perl-status is a Apache HTTP Server handler provided by the
  'mod_perl' module and used to retrieve the server's configuration.");

  script_tag(name:"impact", value:"Requesting the URI /perl-status gives throughout information
  about the currently running Apache to an attacker.");

  script_tag(name:"affected", value:"All Apache installations with an enabled 'mod_perl' module.");

  script_tag(name:"vuldetect", value:"Checks if the /perl-status page of Apache is accessible.");

  script_tag(name:"solution", value:"- If this feature is unused commenting out the appropriate
  section in the web servers configuration is recommended.

  - If this feature is used restricting access to trusted clients is recommended.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

url = "/perl-status";

buf = http_get_cache( item:url, port:port );

# e.g.
# <title>Apache2::Status 4.00</title>
# <title>Apache2::Status 4.01</title>
#
# and something like:
#
#    <p class="hdr">
#      Embedded Perl version <b>v5.8.9</b> for <b>Apache/2.2.31 (Unix) mod_perl/2.0.4 Perl/v5.8.9</b> process <b>153208</b>,<br />
#      running since Thu Feb  6 11:18:25 2020
#    </p>
#
# or:
#
#    <p class="hdr">
#      Embedded Perl version <b>v5.16.3</b> for <b>Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips mod_perl/2.0.11 Perl/v5.16.3</b> process <b>16613</b>,<br />
#      running since Sun Jul  4 03:11:02 2021
#    </p>
if( buf && buf =~ "^HTTP/1\.[01] 200" && egrep( string:buf, pattern:"^\s*(<title>Apache2::Status[^<]+</title>|Embedded Perl version.+for.+Apache)", icase:FALSE ) ) {

  set_kb_item( name:"apache/perl-status/detected", value:TRUE );
  set_kb_item( name:"apache/perl-status/" + port + "/detected", value:TRUE );
  set_kb_item( name:"mod_perl_or_apache_status_info_pages/banner", value:TRUE );

  sv = eregmatch( pattern:"for <b>(Apache/[^>]+)</b>", string:buf );
  if( ! isnull( sv[1] ) )
    set_kb_item( name:"www/perl-status/banner/" + port, value:"Server: " + sv[1] );

  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
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
  script_oid("1.3.6.1.4.1.25623.1.0.117504");
  script_version("2021-06-17T11:51:56+0000");
  script_tag(name:"last_modification", value:"2021-06-18 10:19:50 +0000 (Fri, 18 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-17 08:58:06 +0000 (Thu, 17 Jun 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WordPress Duplicator / Duplicator Pro Plugin Installer File Exposed (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://anonleaks.net/2021/optinfoil/kennotfm-details-zu-hack-und-defacement/");
  script_xref(name:"URL", value:"https://www.synacktiv.com/ressources/advisories/WordPress_Duplicator-1.2.40-RCE.pdf");

  script_tag(name:"summary", value:"One or more installer files of the WordPress plugins Duplicator /
  Duplicator Pro are exposed on the target system.");

  script_tag(name:"vuldetect", value:"Sends crafted HTTP GET requests and checks the responses.");

  script_tag(name:"impact", value:"Exposing these files poses the following risks:

  - Disclosure of sensitive data

  - Installation / overwriting of a WordPress installation on the target host

  - Some older versions of the installer are prone to a remote code execution (RCE) vulnerability");

  script_tag(name:"affected", value:"All systems exposing installation files of the WordPress
  Duplicator / Duplicator Pro plugin.");

  script_tag(name:"solution", value:"Remove the installer files from the target system.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
#include("misc_func.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

tests = make_array(
  # Notes:
  # 1. Normally:
  # <title>Duplicator Installer</title>
  # DUPLICATOR_INSTALLER_EOF  -->
  # but the "Pro" version might have a different strings
  # 2. Normally:
  # <form id='60cb14c6e5c55' method='post' action='http://example.com/wordpress/dup-installer/main.installer.php' />
  # but the "dup-installer" folder can be changed / modified in the installer.php.
  # 3. If the provided "archive" zip file is extracted the file included there is called "installer-backup.php"
  "/installer.php", '(<title>Duplicator[^>]+Installer</title>|DUPLICATOR[^>]*_INSTALLER_EOF\\s*-->|method=["\']post["\'] action=["\'][^>]+/main\\.installer\\.php["\'] />)',
  "/installer-backup.php", '(<title>Duplicator[^>]+Installer</title>|DUPLICATOR[^>]*_INSTALLER_EOF\\s*-->|method=["\']post["\'] action=["\'][^>]+/main\\.installer\\.php["\'] />)',
  # e.g. /* DUPLICATOR-LITE (MYSQL-DUMP BUILD MODE) MYSQL SCRIPT CREATED ON : 2021-06-17 08:44:00 */
  # nb: Normally the file is called like e.g. dup-database__407ffeb-17084338.sql but an admin could
  # rename the file or do similar actions.
  "/database.sql", "/\*\s*DUPLICATOR[^/]+MYSQL[^/]+\*/" );

report = 'The following exposed files were identified:\n';
found = FALSE;

foreach dir( make_list_unique( "/", "/blog", "/wordpress", "/wp", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  foreach file( keys( tests ) ) {

    url = dir + file;

    req = http_get( port:port, item:url );
    res = http_keepalive_send_recv( port:port, data:req );
    if( ! res || res !~ "^HTTP/1\.[01] 200" )
      continue;

    body = http_extract_body_from_response( data:res );
    if( ! body )
      continue;

    pattern = tests[file];

    if( egrep( pattern:pattern, string:body, icase:FALSE ) ) {
      found = TRUE;
      report += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );

      if( file =~ "/installer(-backup)?\.php" ) {

        # nb: As this is "just" a bonus we're only checking on the default "dup-installer" folder
        # to keep the code simple. If it is still desired in the future to check other variants the
        # folder would need to be extracted from e.g.:
        # <form id='60cb14c6e5c55' method='post' action='http://example.com/wordpress/dup-installer/main.installer.php' />

        # e.g.
        # <input type='hidden' name='archive' value='/var/www/html/wp/20210617_test_407ffeb95aee5afb19106121f3d86b98_20210617084338_archive.zip' />
        archive = eregmatch( string:body, pattern:'name=["\']archive["\'] value=["\'][^>]+(/[^>]+_archive\\.zip)["\'] />', icase:FALSE );
        if( archive[1] ) {

          url = dir + archive[1];

          # nb: We're just using HEAD here because the archive might be huge. Note that some servers
          # are disallowing HEAD requests, but as this reporting is only a bonus we don't care.
          req = http_head( item:url, port:port );
          res = http_keepalive_send_recv( port:port, data:req );
          if( res && res =~ "^HTTP/1\.[01] 200" && res =~ "Content-Type\s*:\s*application/zip" )
            report += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
        }
      }
    }
  }
}

if( found ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
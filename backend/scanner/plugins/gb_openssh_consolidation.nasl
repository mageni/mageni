# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108577");
  script_version("2019-05-23T06:42:35+0000");
  script_tag(name:"last_modification", value:"2019-05-23 06:42:35 +0000 (Thu, 23 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-16 12:08:23 +0000 (Thu, 16 May 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("OpenSSH Detection Consolidation");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_dependencies("gb_openssh_remote_detect.nasl", "gb_openssh_ssh_login_detect.nasl");
  script_mandatory_keys("openssh/detected");

  script_xref(name:"URL", value:"https://www.openssh.com/");

  script_tag(name:"summary", value:"The script reports a detected OpenSSH including the
  version number.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("cpe.inc");

if( ! get_kb_item( "openssh/detected" ) )
  exit( 0 );

report = ""; # nb: To make openvas-nasl-lint happy...

foreach source( make_list( "ssh-login", "ssh" ) ) {

  install_list = get_kb_list( "openssh/" + source + "/*/installs" );

  foreach install( install_list ) {

    infos = split( install, sep:"#---#", keep:FALSE );
    if( max_index( infos ) < 3 )
      continue; # Something went wrong and not all required infos are there...

    port     = infos[0];
    install  = infos[1];
    version  = infos[2];
    concl    = infos[3];
    type     = infos[4];
    app_name = "OpenSSH";

    if( type )
      app_name += " " + type;

    # nb: This should contain the "full" Debian version like 7.4p1-10+deb9u4 which is used in the Linux Vuln-VTs
    # to exit earlier if the vuln is already known to be patched.
    #
    # Versions to evaluate:
    # SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u7
    # SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u3
    # SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u4
    # OpenSSH_6.0p1 Debian-4+deb7u7, OpenSSL 1.0.1t  3 May 2016
    # OpenSSH_6.7p1 Debian-5+deb8u3, OpenSSL 1.0.1t  3 May 2016
    # OpenSSH_7.4p1 Debian-10+deb9u4, OpenSSL 1.0.2q  20 Nov 2018
    #
    # Versions to exclude:
    # SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1
    # OpenSSH_4.7p1 Debian-8ubuntu1, OpenSSL 0.9.8g 19 Oct 2007
    #
    if( "debian" >< tolower( concl ) && "ubuntu" >!< tolower( concl ) ) {
      _vers = eregmatch( pattern:"OpenSSH_([^ ]+) Debian-([^,]+)", string:concl, icase:FALSE );
      if( _vers[1] && _vers[2] )
        set_kb_item( name:"openssh/" + port + "/debian_version", value:_vers[1] + "-" + _vers[2] );
    }

    cpe = build_cpe( value:version, exp:"^([.a-zA-Z0-9]+)", base:"cpe:/a:openbsd:openssh:" );
    if( ! cpe )
      cpe = "cpe:/a:openbsd:openssh";

    register_product( cpe:cpe, location:install, port:port, service:source );

    if( report )
      report += '\n\n';
    report += build_detection_report( app:app_name,
                                      version:version,
                                      install:install,
                                      cpe:cpe,
                                      concluded:concl );
  }
}

if( report )
  log_message( port:0, data:report );

exit( 0 );
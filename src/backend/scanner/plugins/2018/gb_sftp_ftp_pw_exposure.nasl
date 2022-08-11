###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sftp_ftp_pw_exposure.nasl 10768 2018-08-04 09:55:39Z cfischer $
#
# SCP/SFTP/FTP Sensitive Data Exposure via Config File
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108346");
  script_version("$Revision: 10768 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-04 11:55:39 +0200 (Sat, 04 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-02-26 08:28:37 +0100 (Mon, 26 Feb 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("SCP/SFTP/FTP Sensitive Data Exposure via Config File");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://blog.sucuri.net/2012/11/psa-sftpftp-password-exposure-via-sftp-config-json.html");
  script_xref(name:"URL", value:"https://kevo.io/security/2013/12/03/dont-commit-your-password/");

  script_tag(name:"summary", value:"The script attempts to identify SCP/SFTP/FTP configuration files containing sensitive data
  at the remote web server.");

  script_tag(name:"insight", value:"Currently the script is checking for the following files:

  - sftp-config.json (Multiple clients, e.g. Sublime SFTP)

  - recentservers.xml, sitemanager.xml, filezilla.xml, FileZilla.xml (FileZilla)

  - WS_FTP.ini, ws_ftp.ini, WS_FTP.INI (WS_FTP)

  - WinSCP.ini, winscp.ini (WinSCP)

  - .vscode/sftp.json (sftp extension for vs code)

  - .vscode/ftp-sync.json (Ftp Sync plugin for Visual Studio Code)

  - .ftpconfig, .remote-sync.json, deployment-config.json (Remote FTP, Remote Sync and SFTP-Deployment packages for Atom.io)

  - ftpsync.settings (FTPSync for Sublime Text)");

  script_tag(name:"vuldetect", value:"Enumerate the remote web server and check if SFTP/FTP configuration
  files are accessible.");

  script_tag(name:"impact", value:"Based on the information provided in this files an attacker might
  be able to gather additional info and/or sensitive data like usernames and passwords.");

  script_tag(name:"solution", value:"A SCP/SFTP/FTP configuration file shouldn't be accessible via a web server.
  Restrict access to it or remove it completely.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  script_timeout(720);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

                    # https://blog.sucuri.net/2012/11/psa-sftpftp-password-exposure-via-sftp-config-json.html
files = make_array( "/sftp-config.json", '^[\\s/]*(The tab key will cycle through the settings|"type": ?"s?ftps?",|"username": ?".+",|"password": ?".+",)',
                    "/ftpsync.settings", '^[\\s]*(upload_on_save: ?(true|false),|username: ?.+,|password: ?.+,)',
                    "/recentservers.xml", "^[\s]*(<FileZilla[0-9]?>|<(Host|Protocol|User|Pass)>.+</(Host|Protocol|User|Pass)>)",
                    "/sitemanager.xml", "^[\s]*(<FileZilla[0-9]?>|<(Host|Protocol|User|Pass)>.+</(Host|Protocol|User|Pass)>)",
                    "/filezilla.xml", "^[\s]*(<FileZilla[0-9]?>|<(Host|Protocol|User|Pass)>.+</(Host|Protocol|User|Pass)>)",
                    "/FileZilla.xml", "^[\s]*(<FileZilla[0-9]?>|<(Host|Protocol|User|Pass)>.+</(Host|Protocol|User|Pass)>)",
                    # http://fileformats.archiveteam.org/wiki/WS_FTP_configuration_files
                    "/WS_FTP.ini", "^[\s]*\[_config_\]",
                    "/ws_ftp.ini", "^[\s]*\[_config_\]",
                    "/WS_FTP.INI", "^[\s]*\[_config_\]",
                    # https://github.com/OliverKohlDSc/Terminals/blob/master/DLLs/Tools/winscp553/WinSCP.ini
                    "/WinSCP.ini", "^[\s]*\[(Configuration|SshHostKeys)\]",
                    "/winscp.ini", "^[\s]*\[(Configuration|SshHostKeys)\]",
                    # https://github.com/liximomo/vscode-sftp/wiki/config
                    "/.vscode/sftp.json", '^[\\s]*("username": ?".+",|"password": ?".+",|"passphrase": ?".+",|"privateKeyPath": ?".+",)',
                    # https://github.com/lukasz-wronski/vscode-ftp-sync/wiki/Sample-FTP-Sync-configs
                    "/.vscode/ftp-sync.json", '^[\\s]*("username": ?".+",|"password": ?".+",|"passphrase": ?".+",|"privateKeyPath": ?".+",)',
                    # https://atom.io/packages/sftp-deployment
                    "/deployment-config.json", '^[\\s]*("type": ?"s?ftp",|"user": ?".+",|"password": ?".+",|"passphrase": ?".+",|"sshKeyFile": ?".+",)',
                    # https://atom.io/packages/remote-sync
                    "/.remote-sync.json", '^[\\s]*("transport": ?"(ftp|scp)",|"username": ?".+",|"password": ?".+",|"passphrase": ?".+",|"keyfile": ?".+",)',
                    # https://atom.io/packages/remote-ftp
                    "/.ftpconfig", '^[\\s]*("protocol": ?"s?ftp",|"user": ?".+",|"pass": ?".+",|"passphrase": ?".+",|"promptForPass": ?(true|false),|"privatekey": ?".+",)' );

report = 'The following files were identified:\n';

port = get_http_port( default:80 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach file( keys( files ) ) {

    url = dir + file;

    if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:files[file], usecache:TRUE ) ) {
      report += '\n' + report_vuln_url( port:port, url:url, url_only:TRUE );
      VULN = TRUE;
    }
  }
}

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

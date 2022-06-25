###############################################################################
# OpenVAS Vulnerability Test
# $Id: mysql_version.nasl 10929 2018-08-11 11:39:44Z cfischer $
#
# Detection of MySQL/MariaDB
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100152");
  script_version("$Revision: 10929 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-11 13:39:44 +0200 (Sat, 11 Aug 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("MySQL/MariaDB Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service1.nasl", "sw_sphinxsearch_detect.nasl");
  script_require_ports("Services/mysql", 3306);

  script_tag(name:"summary", value:"Detects the installed version of
  MySQL/MariaDB.

  Detect a running MySQL/MariaDB by getting the banner, extract the version
  from the banner and store the information in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("misc_func.inc");
include("mysql.inc");
include("cpe.inc");
include("host_details.inc");
include("byte_func.inc");
include("version_func.inc");

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

port = get_kb_item( "Services/mysql" );
if( ! port ) port = 3306;
if( ! get_port_state( port ) ) exit( 0 );

# Don't detect MySQL / MariaDB on SphinxQL
if( get_kb_item( "sphinxsearch/" + port + "/installed" ) ) exit( 0 );

# I found no Plugin that ever set mysql_version ("mysql/version/"). But perhaps i missed something, so i check first if version is set.
if( ! version = get_mysql_version( port:port ) ) {

  soc = open_sock_tcp( port );
  if( ! soc ) exit( 0 );
  buf = recv_mysql_server_handshake( soc:soc );
  close( soc );

  if( ord( buf[0] ) == 255 ) { # connect not allowed

    errno = ord( buf[2] ) << 8 | ord( buf[1] );

    if( errno == ER_HOST_IS_BLOCKED || errno == ER_HOST_NOT_PRIVILEGED ) {

      set_kb_item( name:"MySQL/" + port + "/blocked", value:TRUE );

      if( errno == ER_HOST_IS_BLOCKED ) {
        report =  "Scanner received a ER_HOST_IS_BLOCKED ";
        report += 'error from the remote MySQL/MariaDB server.\nSome ';
        report += "tests may fail. Run 'mysqladmin flush-hosts' to ";
        report += "enable scanner access to this host.";
        log_message( port:port, data:report );
        exit( 0 ); # If the port is blocked, we can't find the server whether it is MySQL/MariaDB.
      } else if( errno == ER_HOST_NOT_PRIVILEGED ) {
        extra  = "Scanner received a ER_HOST_NOT_PRIVILEGED ";
        if( "MariaDB" >< buf ) {
          MariaDB_FOUND = TRUE;
          extra += 'error from the remote MariaDB server.\nSome ';
          extra += "tests may fail. Allow the scanner to access the ";
          extra += "remote MariaDB server for better results.";
        } else if( "MySQL" >< buf ) {
          MySQL_FOUND = TRUE;
          extra += 'error from the remote MySQL server.\nSome ';
          extra += "tests may fail. Allow the scanner to access the ";
          extra += "remote MySQL server for better results.";
        } else {
          extra += 'error from the remote MySQL/MariaDB server.\nSome ';
          extra += "tests may fail. Allow the scanner to access the ";
          extra += "remote MySQL/MariaDB server for better results.";
          log_message( port:port, data:extra );
          exit( 0 );
        }
      }
    }
  } else if( ord( buf[0] ) == 10 ) { #  connect allowed
    if( "MariaDB" >< buf ) {
      MariaDB_FOUND = TRUE;
    } else {
      MySQL_FOUND = TRUE;
    }

    for( i = 1; i < strlen( buf ); i++ ) {
      # server_version is a Null-Terminated String
      if( ord( buf[i] ) != 0 ) {
        version += buf[i];
      } else {
        break;
      }
    }
  }
} else {
   MySQL_FOUND = TRUE;
   getVERSION = TRUE;
}

if( MySQL_FOUND ) {
  if( version ) {
    concluded = version;
    if( ! getVERSION ) {
      set_mysql_version( port:port, version:version );
    }
  } else {
    version = "unknown";
  }

  set_kb_item( name:"MySQL/installed", value:TRUE );
  set_kb_item( name:"MySQL_MariaDB/installed", value:TRUE );

  register_service( port:port, proto:"mysql" );

  if( version_is_less_equal( version:version, test_version:"5.0.96" ) ||
      version_in_range( version:version, test_version:"5.1", test_version2:"5.1.50" ) ||
      version_in_range( version:version, test_version:"5.5", test_version2:"5.5.9" ) ) {
    cpe = build_cpe( value:version, exp:"^([0-9.]+-?[a-zA-Z]+?)", base:"cpe:/a:mysql:mysql:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:mysql:mysql";
  } else {
    cpe = build_cpe( value:version, exp:"^([0-9.]+[a-zA-Z]+?)", base:"cpe:/a:oracle:mysql:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:oracle:mysql";
  }

  if( version != "unknown" )
    set_kb_item( name:"mysql_mariadb/full_banner/" + port, value:version );

  install = port + "/tcp";

  register_product( cpe:cpe, location:install, port:port );

  log_message( data:build_detection_report( app:"MySQL",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:concluded,
                                            extra:extra ),
                                            port:port );
}

if( MariaDB_FOUND ) {  # If MariaDB is found in the port, set the version for MariaDB

  if( version ) {

    ##MariaDB version 10.x and after series is detected as 5.5.x-10.x-MariaDB
    ##So if version comes like that, grep correct part of it.
    if( version =~ "([0-9.]+)-([0-9.]+)-([A-Za-z]+)?" ) {
      version = eregmatch( pattern:"([0-9.]+)-([0-9.]+)-", string:version );
      version = version[2];
    } else {
      # Regex for old MariaDB versions like 5.5.49-MariaDB
      version = eregmatch( pattern:"([0-9.]+)-", string:version );
      version = version[1];
    }
    set_mariadb_version( port:port, version:version );

    # Regex to not print the changing buf with binary data in the report
    # buf is e.g. 5.5.5-10.1.19-MariaDB or 5.5.49-MariaDB
    concluded = egrep( pattern:"([0-9.]+)(-([0-9.]+))?-", string:buf );
    set_kb_item( name:"mysql_mariadb/full_banner/" + port, value:concluded );
  } else {
    version = "unknown";
  }

  set_kb_item( name:"MariaDB/installed", value:TRUE );
  set_kb_item( name:"MySQL_MariaDB/installed", value:TRUE );

  register_service( port:port, proto:"mysql" );

  cpe = build_cpe( value:version, exp:"^([0-9.]+-?[a-zA-Z]+?)", base:"cpe:/a:mariadb:mariadb:" );
  if( isnull( cpe ) )
    cpe = "cpe:/a:mariadb:mariadb";

  install = port + "/tcp";

  register_product( cpe:cpe, location:install, port:port );

  log_message( data:build_detection_report( app:"MariaDB",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:concluded,
                                            extra:extra ),
                                            port:port );
}

exit( 0 );

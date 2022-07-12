###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_database_open_access_vuln.nasl 11374 2018-09-13 12:45:05Z asteins $
#
# Database Open Access Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902799");
  script_version("$Revision: 11374 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-13 14:45:05 +0200 (Thu, 13 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-03-01 17:10:53 +0530 (Thu, 01 Mar 2012)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Database Open Access Vulnerability");
  script_copyright("Copyright (C) 2012 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_dependencies("oracle_tnslsnr_version.nasl", "gb_ibm_db2_remote_detect.nasl", "postgresql_detect.nasl",
                      "mssqlserver_detect.nasl", "gb_ibm_soliddb_detect.nasl", "mysql_version.nasl",
                      "secpod_open_tcp_ports.nasl", "gb_open_udp_ports.nasl");
  script_mandatory_keys("OpenDatabase/found");

  script_xref(name:"URL", value:"https://www.pcisecuritystandards.org/security_standards/index.php?id=pci_dss_v1-2.pdf");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to obtain the sensitive
  information of the database.");
  script_tag(name:"insight", value:"Do not restricting direct access of databases to the remote systems.");
  script_tag(name:"summary", value:"The host is running a Database server and is prone to information
  disclosure vulnerability.");
  script_tag(name:"affected", value:"- MySQL/MariaDB

  - IBM DB2

  - PostgreSQL

  - IBM solidDB

  - Oracle Database

  - Microsoft SQL Server");
  script_tag(name:"solution", value:"Restrict Database access to remote systems.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc"); # For make_list_unique()
include("network_func.inc");
include("misc_func.inc");

function is_oracle_db( port ) {

  local_var port, ver;

  ver = get_kb_item( "oracle_tnslsnr/" + port + "/version" );
  if( ver )
    return TRUE;
  else
    return FALSE;
}

function is_ibm_db2( port ) {

  local_var port, ibmVer;

  ibmVer = get_kb_item( "IBM-DB2/Remote/" + port + "/ver" );
  if( ibmVer )
    return TRUE;
  else
    return FALSE;
}

function is_postgre_sql( port ) {

  local_var port, psqlver;

  psqlver = get_kb_item( "PostgreSQL/Remote/" + port + "/Ver" );
  if( psqlver )
    return TRUE;
  else
    return FALSE;
}

function is_solid_db( port ) {

  local_var port, solidVer;

  solidVer = get_kb_item( "soliddb/" + port + "/version" );
  if( solidVer )
    return TRUE;
  else
    return FALSE;
}

function is_mssql( port ) {

  local_var port, mssql_rls;

  mssql_rls = get_kb_item( "MS/SQLSERVER/" + port + "/releasename" );
  if( mssql_rls )
    return TRUE;
  else
    return FALSE;
}

function is_mysql( port ) {

  local_var port, myVer;

  myVer = get_kb_item( "mysql/version/" + port );
  if( myVer )
    return TRUE;
  else
    return FALSE;
}

function is_mariadb( port ) {

  local_var port, mariaVer;

  mariaVer = get_kb_item( "mariadb/version/" + port );
  if( mariaVer )
    return TRUE;
  else
    return FALSE;
}

# nb: This function is already checking for get_port_state()
# and is returning an empty list if no port was found
ports = get_all_tcp_ports_list();
# Adding the default ports if unscanned_closed = no
ports = make_list_unique( ports, 5432, 1433, 1315, 3306, 1521 );

foreach port( ports ) {

  oracle_db = is_oracle_db( port:port );
  if( oracle_db ) {
    log_message( data:"Oracle database can be accessed by remote attackers", port:port );
    continue;
  }

  mysql = is_mysql( port:port );
  if( mysql ) {
    log_message( data:"MySQL can be accessed by remote attackers", port:port );
    continue;
  }

  mariadb = is_mariadb( port:port );
  if( mariadb ) {
    log_message( data:"MariaDB can be accessed by remote attackers", port:port );
    continue;
  }

  postgre_sql = is_postgre_sql( port:port );
  if( postgre_sql ) {
    log_message( data:"PostgreSQL database can be accessed by remote attackers", port:port );
    continue;
  }

  solid_db = is_solid_db( port:port );
  if( solid_db ) {
    log_message( data:"SolidDB can be accessed by remote attackers", port:port);
    continue;
  }

  mssql = is_mssql();
  if( mssql ) {
    log_message( data:"Microsoft SQL Server can be accessed by remote attackers", port:port );
    continue;
  }
}

# nb: This function is already checking for get_udp_port_state()
# and is returning an empty list if no port was found
udp_ports = get_all_udp_ports_list();
# Adding the default port if unscanned_closed_udp = no
udp_ports = make_list_unique( udp_ports, 523 );

foreach udp_port( udp_ports ) {
  ibm_db2 = is_ibm_db2( port:udp_port );
  if( ibm_db2 ) {
    log_message( data:"IBM DB2 can be accessed by remote attackers", port:udp_port, proto:"udp" );
    continue;
  }
}

exit( 0 );
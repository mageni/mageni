# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.116184");
  script_version("2023-11-24T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-11-24 05:05:36 +0000 (Fri, 24 Nov 2023)");
  script_tag(name:"creation_date", value:"2021-04-08 08:00:00 +0000 (Thu, 08 Apr 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("PostgreSQL: Database settings for Compliance Tests");

  script_category(ACT_SETTINGS);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Compliance");
  script_dependencies("compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Port", type:"entry", value:"5432", id:1);
  script_add_preference(name:"Version", type:"entry", value:"", id:2);
  script_add_preference(name:"Username", type:"entry", value:"", id:3);
  script_add_preference(name:"Password", type:"password", value:"", id:4);
  script_add_preference(name:"Database", type:"entry", value:"", id:5);

  script_tag(name:"summary", value:"Allows to set various PostgreSQL database settings used for
  compliance tests.");

  script_tag(name:"insight", value:"- Port: Enter the port used for PostgreSQL

  If applicable, also enter:

  - Version: The version number (12/11/10/9.6)

  - Username: The database user

  - Password: The password for the database user

  - Database: The database name to connect to");

  exit(0);
}

port = script_get_preference( "Port", id:1 );
if ( port != "" )
  set_kb_item( name:"Policy/PostgreSQL/port", value:port );
else
  set_kb_item( name:"Policy/PostgreSQL/port", value:"5432" );

version = script_get_preference( "Version", id:2 );
if ( version != "" )
  set_kb_item( name:"Policy/PostgreSQL/version", value:version );

username = script_get_preference( "Username", id:3 );
if ( username != "" )
  set_kb_item( name:"Policy/PostgreSQL/username", value:username );

password = script_get_preference( "Password", id:4 );
if ( password != "" )
  set_kb_item( name:"Policy/PostgreSQL/password", value:password );

database = script_get_preference( "Database", id:5 );
if ( database != "" )
  set_kb_item( name:"Policy/PostgreSQL/database", value:database );

exit( 0 );

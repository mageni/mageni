###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_orientdb_rce_vuln.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# OrientDB Server Remote Code Execution Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:orientdb:orientdb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112079");
  script_version("$Revision: 11874 $");
  script_cve_id("CVE-2017-11467");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-12 09:13:31 +0200 (Thu, 12 Oct 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("OrientDB Server Remote Code Execution Vulnerability");

  script_tag(name:"summary", value:"OrientDB does not enforce privilege requirements during 'where' or 'fetchplan'
  or 'order by' use, which allows remote attackers to execute arbitrary OS commands via a crafted request.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"OrientDB uses RBAC model for authentication schemes. By default an OrientDB has 3 roles - admin, writer and reader.
  These have their usernames same as the role. For each database created on the server, it assigns by default these 3 users.

  The privileges of the users are:

  admin - access to all functions on the database without any limitation

  reader - read-only user. The reader can query any records in the database, but can't modify or delete them. It has no access to internal information, such as the users and roles themselves

  writer - same as the 'reader', but it can also create, update and delete records

  ORole structure handles users and their roles and is only accessible by the admin user. OrientDB requires oRole read permissions to allow the user
  to display the permissions of users and make other queries associated with oRole permissions.

  From version 2.2.x and above whenever the oRole is queried with a where, fetchplan and order by statements,
  this permission requirement is not required and information is returned to unprivileged users.

  Since OrientDB has a function where one could execute groovy functions and this groovy wrapper doesn't have a sandbox and exposes system functionalities,
  it is possible to run any command.");

  script_tag(name:"affected", value:"OrientDB Server version 2.2.x to 2.2.22");

  script_tag(name:"solution", value:"Upgrade to OrientDB Server version 2.2.23 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.heavensec.org/?p=1703");
  script_xref(name:"URL", value:"https://github.com/orientechnologies/orientdb/wiki/OrientDB-2.2-Release-Notes#2223---july-11-2017");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_orientdb_server_detect.nasl");
  script_mandatory_keys("OrientDB/Installed");
  script_require_ports("Services/www", 2480);
  script_xref(name:"URL", value:"http://orientdb.com/");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE)){
 exit(0);
}

if(!ver = get_app_version(cpe:CPE, port:port)){
 exit(0);
}

if(version_in_range(version:ver, test_version:"2.2", test_version2:"2.2.22"))
{
  report = report_fixed_ver(installed_version:ver, fixed_version:"2.2.23");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);

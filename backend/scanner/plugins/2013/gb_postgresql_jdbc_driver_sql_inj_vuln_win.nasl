###############################################################################
# OpenVAS Vulnerability Test
#
# PostgreSQL JDBC Driver SQL Injection Vulnerability (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803220");
  script_version("2019-05-20T11:12:48+0000");
  script_cve_id("CVE-2012-1618");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-20 11:12:48 +0000 (Mon, 20 May 2019)");
  script_tag(name:"creation_date", value:"2013-01-24 19:16:05 +0530 (Thu, 24 Jan 2013)");
  script_name("PostgreSQL JDBC Driver SQL Injection Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2012/Mar/125");
  script_xref(name:"URL", value:"https://bugzilla.novell.com/show_bug.cgi?id=754273");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2012-03/0126.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/111239/PostgreSQL-JDBC-Driver-8.1-SQL-Injection.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_postgresql_detect_win.nasl");
  script_mandatory_keys("PostgreSQL/Win/Ver");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to manipulate SQL queries by
  injecting arbitrary SQL code and gain sensitive information.");

  script_tag(name:"affected", value:"PostgreSQL JDBC Driver versions 8.1 on Windows");

  script_tag(name:"insight", value:"An error exists within the JDBC driver which fails to escape unspecified
  JDBC statement parameters.");

  script_tag(name:"solution", value:"Upgrade to PostgreSQL JDBC Driver versions 8.2 or later.");

  script_tag(name:"summary", value:"This host is installed with PostgreSQL with JDBC Driver and is
  prone to sql injection vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

pgsqlVer = get_kb_item("PostgreSQL/Win/Ver");
if(!pgsqlVer || pgsqlVer !~ "^9\.1")
  exit(0);

pgkey = "SOFTWARE\EnterpriseDB\pgJDBC";
if(!registry_key_exists(key:pgkey)){
  exit(0);
}

pgjdbcVer = registry_get_sz(key:pgkey, item:"Version");
if(pgjdbcVer && pgjdbcVer =~ "^8\.1"){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

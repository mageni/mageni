###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_navis_webaccess_sql_inj_vuln.nasl 11725 2018-10-02 10:50:50Z asteins $
#
# Navis WebAccess SQL Injection Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = 'cpe:/a:navis:webaccess';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106195");
  script_version("$Revision: 11725 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-02 12:50:50 +0200 (Tue, 02 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-08-23 08:07:26 +0700 (Tue, 23 Aug 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2016-5817");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Navis WebAccess SQL Injection Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_navis_webaccess_detect.nasl");
  script_mandatory_keys("navis_webaccess/installed");

  script_tag(name:"summary", value:"Navis WebAccess is prone to an SQL injection vulnerability.");

  script_tag(name:"insight", value:"The WebAccess application does not properly sanitize input that
may allow a remote attacker to read, modify, and affect availability of data in the SQL database.");

  script_tag(name:"impact", value:"Successful exploitation of the vulnerability may allow a remote
attacker to compromise the confidentiality, integrity, and availablility of the SQL database.");

  script_tag(name:"affected", value:"Navis WebAccess, all versions released prior to August 10, 2016");

  script_tag(name:"solution", value:"Install the patch provided by the vendor.");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-16-231-01");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40216/");

  script_tag(name:"vuldetect", value:"Tries to cause an SQL error and checks the response.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

url = "/express/showNotice.do?report_type=1&GKEY=2'";

if (http_vuln_check(port: port, url: url, pattern: "ORA-00933: SQL command not properly ended")) {
  security_message(port: port);
  exit(0);
}

exit(0);

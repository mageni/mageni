###############################################################################
# OpenVAS Vulnerability Test
# $Id: ruby_WEBrick_37710.nasl 14326 2019-03-19 13:40:32Z jschulte $
#
# Ruby WEBrick Terminal Escape Sequence in Logs Command Injection Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100445");
  script_version("$Revision: 14326 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:40:32 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-01-13 11:20:27 +0100 (Wed, 13 Jan 2010)");
  script_bugtraq_id(37710);
  script_cve_id("CVE-2009-4492");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ruby WEBrick Terminal Escape Sequence in Logs Command Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37710");
  script_xref(name:"URL", value:"http://www.ruby-lang.org");
  script_xref(name:"URL", value:"http://www.ruby-lang.org/en/news/2010/01/10/webrick-escape-sequence-injection/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/508830");

  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("WEBrick/banner");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");
  script_tag(name:"summary", value:"Ruby WEBrick is prone to a command-injection vulnerability because it
 fails to adequately sanitize user-supplied input in log files.");
  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary commands in
 a terminal.");
  script_tag(name:"affected", value:"Versions *prior to* the following are affected:

 Ruby 1.8.6 patchlevel 388 Ruby 1.8.7 patchlevel 249 Ruby 1.9.1 patchlevel 378");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:8080);

banner = get_http_banner(port: port);

if(!banner && "Server: WEBrick" >!< banner) exit(0);

if(!matches = eregmatch(pattern: "Server: WEBrick/[0-9.]+ \(Ruby/([0-9.]+)/([0-9]{4}-[0-9]{2}-[0-9]{2})\)", string: banner))exit(0);
if(isnull(matches[1]) || isnull(matches[2]))exit(0);

release = matches[1];
release_date = matches[2];

if(version_is_equal(version: release, test_version: "1.8.6") ||
   version_is_equal(version: release, test_version: "1.8.7") ||
   version_is_equal(version: release, test_version: "1.9.1")) {

    rdate = split(release_date, sep: "-", keep: FALSE);
    if(isnull(rdate[0]) || isnull(rdate[1]) || isnull(rdate[2]))exit(0);

    if(int(rdate[0]) < 2010) {
      VULN = TRUE;
    }
    else if(int(rdate[0]) == 2010 && int(rdate[1]) == 1 && int(rdate[2]) < 10) {
      VULN = TRUE;
    }

    if(VULN) {
      report = report_fixed_ver(installed_version:release, fixed_version:"1.8.6/1.8.7/1.9.1");
      security_message(port:port, data:report);
      exit(0);
    }
}

exit(99);

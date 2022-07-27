###############################################################################
# OpenVAS Vulnerability Test
#
# RT Session Fixation Vulnerability
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100386");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2009-12-09 13:16:50 +0100 (Wed, 09 Dec 2009)");
  script_bugtraq_id(37162);
  script_cve_id("CVE-2009-3585");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_name("RT Session Fixation Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37162");
  script_xref(name:"URL", value:"http://lists.bestpractical.com/pipermail/rt-announce/2009-November/000177.html");
  script_xref(name:"URL", value:"http://lists.bestpractical.com/pipermail/rt-announce/2009-November/000176.html");
  script_xref(name:"URL", value:"http://www.bestpractical.com/rt/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("rt_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("RequestTracker/installed");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"RT is prone to a session-fixation vulnerability.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to hijack a user's session and gain
  unauthorized access to the affected application.");

  script_tag(name:"affected", value:"The issue affects RT 3.0.0 through 3.8.5.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!version = get_kb_item(string("www/", port, "/rt_tracker")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_in_range(version: vers, test_version: "3", test_version2: "3.8.5")) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);

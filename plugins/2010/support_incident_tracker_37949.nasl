###############################################################################
# OpenVAS Vulnerability Test
#
# Support Incident Tracker Blank Password Authentication Bypass Vulnerability
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100467");
  script_version("2019-05-14T08:13:05+0000");
  script_tag(name:"last_modification", value:"2019-05-14 08:13:05 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-01-26 20:04:43 +0100 (Tue, 26 Jan 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-1596");
  script_bugtraq_id(37949);

  script_name("Support Incident Tracker Blank Password Authentication Bypass Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37949");
  script_xref(name:"URL", value:"http://sitracker.sourceforge.net");
  script_xref(name:"URL", value:"http://sitracker.org/wiki/ReleaseNotes351");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("support_incident_tracker_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("sit/installed");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released an update. Please see the references for more
  information.");

  script_tag(name:"summary", value:"Support Incident Tracker (SiT!) is prone to an authentication-bypass
  vulnerability.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to gain unauthorized access to the
  affected application.");

  script_tag(name:"affected", value:"Versions prior to Support Incident Tracker (SiT!) 3.51 are vulnerable.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);

if(!version = get_kb_item(string("www/", port, "/support_incident_tracker")))
  exit(0);

if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))
  exit(0);

vers = matches[1];

if(!isnull(vers) && vers >!< "unknown") {
  if(version_is_less(version: vers, test_version: "3.51")) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);
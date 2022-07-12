###############################################################################
# OpenVAS Vulnerability Test
#
# Mahara Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.100334");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2009-11-04 12:36:10 +0100 (Wed, 04 Nov 2009)");
  script_bugtraq_id(36893, 36892);
  script_cve_id("CVE-2009-3298", "CVE-2009-3299");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("Mahara Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36893");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36892");
  script_xref(name:"URL", value:"http://wiki.mahara.org/Release_Notes/1.1.7");
  script_xref(name:"URL", value:"http://mahara.org/interaction/forum/topic.php?id=1169");
  script_xref(name:"URL", value:"http://mahara.org/interaction/forum/topic.php?id=1170");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("secpod_mahara_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mahara/detected");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  details.");

  script_tag(name:"summary", value:"Mahara is prone to a security-bypass vulnerability and to a to a
  cross-site scripting vulnerability.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to reset the application's
  administrator password or to execute arbitrary script code in the
  browser of an unsuspecting user in the context of the affected site.");

  script_tag(name:"affected", value:"Versions prior to Mahara 1.0.13 and 1.1.7 are affected.");

  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!version = get_kb_item(string("www/", port, "/Mahara")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(!isnull(vers) && vers >!< "unknown") {
  if(version_in_range(version: vers, test_version: "1.0", test_version2: "1.0.12") ||
     version_in_range(version: vers, test_version: "1.1", test_version2: "1.1.6")) {
    security_message(port:port, data:"The target host was found to be vulnerable.");
    exit(0);
  }
}

exit(99);

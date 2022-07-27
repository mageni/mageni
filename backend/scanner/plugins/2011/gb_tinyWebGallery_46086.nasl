###############################################################################
# OpenVAS Vulnerability Test
#
# TinyWebGallery Cross Site Scripting and Local File Include Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103055");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2011-02-02 13:26:27 +0100 (Wed, 02 Feb 2011)");
  script_bugtraq_id(46086);

  script_name("TinyWebGallery Cross Site Scripting and Local File Include Vulnerabilities");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/46086");
  script_xref(name:"URL", value:"http://www.tinywebgallery.com/en/overview.php");

  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("TinyWebGallery_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("tinywebgallery/detected");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"summary", value:"TinyWebGallery is prone to local file-include and cross-site scripting
  vulnerabilities because the application fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"A remote attacker may leverage the cross-site scripting issue to
  execute arbitrary script code in the browser of an unsuspecting
  user in the context of the affected site. This may allow the
  attacker to steal cookie-based authentication credentials and to
  launch other attacks.

  Exploiting the local file-include issue allows the attacker to view
  and subsequently execute local files within the context of the
  webserver process.");

  script_tag(name:"affected", value:"TinyWebGallery 1.8.3 is vulnerable. Other versions may also be
  affected.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);

if(vers = get_version_from_kb(port:port,app:"TinyWebGallery")) {
  if(version_is_equal(version: vers, test_version: "1.8.3")) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);

# OpenVAS Vulnerability Test
# Description: php < 4.3.8
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.13650");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(10724, 10725);
  script_cve_id("CVE-2004-0594", "CVE-2004-0595");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("php < 4.3.8");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("PHP/banner");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution", value:"Upgrade to PHP 4.3.8");
  script_tag(name:"summary", value:"The remote host is running a version of PHP 4.3 which is older or equal to 4.3.7.

  There is a bug in the remote version of this software which may
  allow an attacker to execute arbitrary code on the remote host if the option
  memory_limit is set. Another bug in the function strip_tags() may allow
  an attacker to bypass content-restrictions when submitting data and may
  lead to cross-site-scripting issues.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
php = get_http_banner(port:port);
if(!php || "PHP" >!< php)
  exit(0);

if(ereg(pattern:"PHP/4\.3\.[0-7][^0-9]", string:php)) {
  security_message(port:port);
  exit(0);
}

exit(99);
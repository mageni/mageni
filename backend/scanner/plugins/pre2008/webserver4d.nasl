# OpenVAS Vulnerability Test
# Description: Webserver 4D Cleartext Passwords
#
# Authors:
# Jason Lidow <jason@brandx.net>
#
# Copyright:
# Copyright (C) 2002 Jason Lidow <jason@brandx.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.11151");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(5803);
  script_cve_id("CVE-2002-1521");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Webserver 4D Cleartext Passwords");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Jason Lidow <jason@brandx.net>");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Web_Server_4D/banner");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution", value:"Contact the vendor for an update.");

  script_tag(name:"summary", value:"The remote host is running Webserver 4D 3.6 or lower.

  Version 3.6 of this service stores all usernames and passwords in cleartext.
  File: C:\Program Files\MDG\Web Server 4D 3.6.0\Ws4d.4DD");

  script_tag(name:"impact", value:"A local attacker may use this flaw to gain unauthorized privileges
  on this host.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if(!banner || "Web_Server_4D" >!< banner)
  exit(0);

line = egrep(pattern:"^Server.*", string:banner);
if(line) {
  report = "The following banner was received: " + line;
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
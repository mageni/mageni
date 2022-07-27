# OpenVAS Vulnerability Test
# Description: phpBB Fetch All < 2.0.12
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
  script_oid("1.3.6.1.4.1.25623.1.0.14226");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(10868, 10893);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("phpBB Fetch All < 2.0.12");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("phpbb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpBB/installed");

  script_tag(name:"solution", value:"Upgrade to phpBB Fetch All 2.0.12 or later.");

  script_tag(name:"summary", value:"The remote host is running a version of phpBB FetchAll older than 2.0.12.");

  script_tag(name:"insight", value:"It is reported that this version of phpBB Fetch All is susceptible to an SQL
  injection vulnerability. This issue is due to a failure of the application to properly sanitize user-supplied
  input before using it in an SQL query.

  The successful exploitation of this vulnerability depends on the implementation of the web application that includes
  phpBB Fetch All as a component. It may or may not be possible to effectively pass
  malicious SQL statements to the underlying function.");

  script_tag(name:"impact", value:"Successful exploitation could result in compromise of the application,
  disclosure or modification of data or may permit an attacker to exploit
  vulnerabilities in the underlying database implementation.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/phpBB");
if ( ! kb )
  exit(0);

matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
location = matches[2];

res = http_get_cache(item:location + "/index.php", port:port);
if(!res)
  exit(0);

if(ereg(pattern:"Fetch by phpBB Fetch All ([01]\..*|2\.0\.([0-9]|1[01])[^0-9])", string:res)) {
  security_message(port:port);
  exit(0);
}

exit(99);
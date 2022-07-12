###############################################################################
# OpenVAS Vulnerability Test
#
# ePO console Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100331");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-05-05T09:44:01+0000");
  script_tag(name:"last_modification", value:"2020-05-06 11:41:12 +0000 (Wed, 06 May 2020)");
  script_tag(name:"creation_date", value:"2009-11-01 17:45:48 +0100 (Sun, 01 Nov 2009)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("ePO console Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Service detection");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This host is running an ePolicy Orchestrator (ePo) console.");

  exit(0);
}

include("http_func.inc");

port = http_get_port(default:80);

data = "xxxxx";

req = string("POST /spipe/pkg?Source=Agent_3.0.0 HTTP/1.0\r\n",
             "Content-Length: ", strlen(data),
             "\r\n",
             "\r\n",
             data);
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);
if(!buf)
  exit(0);

if("202 OK" >< buf) {
  blen = strlen(buf);
  str  = substr(buf,blen-3);
  if(hexstr(str) == "0d0a20") {
    log_message(port:port);
  }
}

exit(0);

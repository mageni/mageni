# OpenVAS Vulnerability Test
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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
  script_oid("1.3.6.1.4.1.25623.1.0.18532");
  script_version("2020-02-04T08:24:46+0000");
  script_tag(name:"last_modification", value:"2020-02-04 08:24:46 +0000 (Tue, 04 Feb 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Enterasys Dragon Enterprise Reporting Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("Product detection");
  script_dependencies("secpod_apache_detect.nasl", "global_settings.nasl");
  script_require_ports(9443);
  script_require_keys("apache/installed");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The remote host is running the Enterasys Dragon Enterprise Reporting on
  this port.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

port = 9443;
if(!get_port_state(port))
  exit(0);

req = http_get(item:"/dragon/login.jsp", port:port);
res = http_send_recv(data:req, port:port);

if(res && ">Dragon Enterprise Reporting<" >< res) {

  version = "unknown";
  cpe = "cpe:/a:enterasys:dragon_enterprise_reporting";

  register_and_report_cpe(app:"Enterasys Dragon Enterprise Reporting",
                          ver:version,
                          base:cpe,
                          expr:"([0-9.]+)",
                          insloc:port + "/tcp",
                          regPort:port,
                          regService:"www");
}

exit(0);

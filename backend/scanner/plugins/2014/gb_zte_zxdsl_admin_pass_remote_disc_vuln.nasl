###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zte_zxdsl_admin_pass_remote_disc_vuln.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# ZTE ZXDSL Modem /adminpasswd.cgi Admin Password Remote Disclosure Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804798");
  script_version("$Revision: 11402 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-11-14 16:42:38 +0530 (Fri, 14 Nov 2014)");
  script_name("ZTE ZXDSL Modem /adminpasswd.cgi Admin Password Remote Disclosure Vulnerability");
  script_cve_id("CVE-2014-9184", "CVE-2014-9183");

  script_tag(name:"summary", value:"This host is installed with ZTE ZXDSL
  Modem and is prone to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read admin password or not.");

  script_tag(name:"insight", value:"Flaw is due to the source information of
  /adminpasswd.cgi script displays admin password information in cleartext.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to admin password information.");

  script_tag(name:"affected", value:"ZTE ZXDSL 831CI Modem");

  script_tag(name:"solution", value:"No known solution was made available
  for at least one year since the disclosure of this vulnerability. Likely none will
  be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another
  one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2014/Nov/40");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/35203");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/533929/30/0/threaded");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:80);

## So Doing more extra check
if(http_vuln_check(port:http_port, url:"/adminpasswd.cgi", check_header:TRUE,
   pattern:">Admin account.*configuration of your ADSL<",
   extra_check:make_list(">User Name:<", ">New Password:<",
                         ">Admin Account<", "btnApplyAdmin")))
{
  security_message(http_port);
  exit(0);
}

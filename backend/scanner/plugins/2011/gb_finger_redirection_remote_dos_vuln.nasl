###############################################################################
# OpenVAS Vulnerability Test
#
# Finger Redirection Remote Denial of Service Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802231");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2011-08-10 13:49:51 +0200 (Wed, 10 Aug 2011)");
  script_cve_id("CVE-1999-0106");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Finger Redirection Remote Denial of Service Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Finger abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/finger", 79);

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/47");
  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?id=10073");
  script_xref(name:"URL", value:"http://www.iss.net/security_center/reference/vuln/finger-bomb.htm");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker to use this computer as a relay
  to gather information on a third-party network or cause a denial of service.");

  script_tag(name:"affected", value:"GNU Finger.");

  script_tag(name:"insight", value:"The flaw exists due to finger daemon allows redirecting a finger request to
  remote sites using the form finger 'username@hostname1@hostname2'.");

  script_tag(name:"solution", value:"Upgrade to GNU finger 1.37 or later.");

  script_tag(name:"summary", value:"This host is running Finger service and is prone to denial of
  service vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

port = get_kb_item("Services/finger");
if(!port){
  port = 79;
}

if(! get_port_state(port)){
  exit(0);
}

host = get_host_name();

soc = open_sock_tcp(port);
if(! soc){
  exit(0);
}

banner = recv(socket:soc, length:2048, timeout:5);
if(banner) {
  exit(0);
}

req = "root@" + host + "\r\n";

send(socket: soc, data: req);
res = recv(socket:soc, length:65535);
close(soc);

res = tolower(res);
if( res && "such user" >!< res && "doesn't exist" >!< res &&
    "???" >!< res && "invalid" >!< res && "forward" >!< res){
  security_message(port:port);
  exit(0);
}

exit(99);

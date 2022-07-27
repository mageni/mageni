###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_finger_unused_account_disc_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Finger Service Unused Account Disclosure Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902555");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-08-29 16:22:41 +0200 (Mon, 29 Aug 2011)");
  script_cve_id("CVE-1999-0197");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Finger Service Unused Account Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/8378");
  script_xref(name:"URL", value:"http://www.iss.net/security_center/reference/vuln/finger-unused-accounts.htm");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Finger abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/finger", 79);
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain sensitive information
  that could aid in further attacks.");
  script_tag(name:"affected", value:"GNU Finger.");
  script_tag(name:"insight", value:"The flaw exists due to finger service display a list of unused accounts for
  a 'finger 0@host' request.");
  script_tag(name:"solution", value:"Disable finger service, or install a finger service or daemon that
  limits the type of information provided.");
  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"summary", value:"This host is running Finger service and is prone to information
  disclosure vulnerability.");
  exit(0);
}


port = get_kb_item("Services/finger");
if(!port){
  port = 79;
}

if(! get_port_state(port)){
  exit(0);
}

soc = open_sock_tcp(port);
if(! soc){
  exit(0);
}

banner = recv(socket:soc, length:2048, timeout:5);
if(banner) {
  exit(0);
}

send(socket: soc, data: string("0\r\n"));
res = recv(socket:soc, length:2048);
close(soc);

if(strlen(res) > 150)
{
  if("adm" >< res || "bin" >< res || "daemon" >< res ||
      "lp" >< res || "sys" >< res){
    security_message(port);
  }
}

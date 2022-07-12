###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_d2d_storeonce_backdoor_06_13.nasl 13571 2019-02-11 11:00:12Z cfischer $
#
# HP D2D/StorOnce Storage Unit Backdoor
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103746");
  script_version("$Revision: 13571 $");
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2013-2342");
  script_tag(name:"last_modification", value:"$Date: 2019-02-11 12:00:12 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2013-06-25 14:06:35 +0200 (Tue, 25 Jun 2013)");
  script_name("HP D2D/StorOnce Storage Unit Backdoor");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available");

  script_xref(name:"URL", value:"http://www.lolware.net/hpstorage.html");

  script_tag(name:"summary", value:"HP D2D/StorOnce Storage Units are prone to a security-bypass vulnerability.");

  script_tag(name:"insight", value:"The HP D2D/StorOnce Storage Units contains a backdoor. SSH access is all that's
  required to remotely compromise HP StoreOnce backup systems. Entering the user
  name 'HPSupport' and the password 'badg3r5' causes the system to open an
  undocumented administrator account.");

  script_tag(name:"solution", value:"Disable SSH access or disallow remote SSH access from outside your network.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("ssh_func.inc");

port = get_ssh_port( default:22 );
if( ! soc = open_sock_tcp( port ) ) exit( 0 );
if( ssh_broken_random_login( port:port ) ) exit( 0 );

login = "HPSupport";
pass  = "badg3r5";

login = ssh_login( socket:soc, login:login, password:pass );

if( login == 0 ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
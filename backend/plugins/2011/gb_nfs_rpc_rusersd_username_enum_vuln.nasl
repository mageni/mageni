# Copyright (C) 2011 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902473");
  script_version("2021-10-20T09:17:04+0000");
  script_tag(name:"last_modification", value:"2021-10-20 10:23:51 +0000 (Wed, 20 Oct 2021)");
  script_tag(name:"creation_date", value:"2011-08-31 13:40:07 +0200 (Wed, 31 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-1999-0626");
  script_name("Nfs-utils 'rusersd' User Enumeration Vulnerability");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_family("General");
  script_dependencies("secpod_rpc_portmap_udp.nasl");
  script_mandatory_keys("rpc/portmap/udp/detected");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?ctype=cve&id=CVE-1999-0626");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to extract the list
  of users currently logged in.");

  script_tag(name:"affected", value:"nfs-utils rpc version 1.2.3 prior.");

  script_tag(name:"insight", value:"The flaw is due to an error in remote rusers server which allows
  to extract the list of users currently logged in the remote host.

  Remark: NIST don't see 'configuration issues' as software flaws so the referenced CVE has a
  severity of 0.0. The severity of this VT has been raised by Greenbone to still report a
  configuration issue on the target.");

  script_tag(name:"summary", value:"The RPC rusersd service is prone to a user name enumeration
  vulnerability.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("rpc.inc");
include("byte_func.inc");

port = rpc_get_port(program:100002, protocol:IPPROTO_UDP);
if(!port)
  exit(0);

soc = open_sock_udp(port);
if(!soc)
  exit(0);

req = raw_string(0x25, 0xC8, 0x20, 0x4C, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
                 0x00, 0x01, 0x86, 0xA2, 0x00, 0x00,
                 0x00, 0x02, 0x00, 0x00, 0x00, 0x02,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00);

send(socket:soc, data:req);

resp = recv(socket:soc, length:4096);
close(soc);

if(strlen(resp) > 28) {
  nenty = ord(resp[27]);
  if(nenty == 0)
    exit(0);

  start = 32;

  for(i = 0; i < nenty; i = i + 1) {
    timtl = "";
    len = 0;
    for(j = start; ord(resp[j]) && len < 16; j = j + 1) {
      if(j > strlen(resp))
        exit(0);

      timtl = string(timtl, resp[j]);
      len = len + 1;
    }

    start = start + 12;
    user = "";
    len = 0;
    for(j = start; ord(resp[j]) && len < 16; j = j + 1) {
      if(j > strlen(resp))
        exit(0);

      user = string(user, resp[j]);
      len = len + 1;
    }

    start = start + 12;
    usrFrom = "";
    len  = 0;
    for(j = start; ord(resp[j]) && len < 16; j = j + 1) {
      len = len + 1;
      if(j > strlen(resp))
        exit(0);

      usrFrom = string(usrFrom, resp[j]);
    }

    start = start + 28;

    if(strlen(usrFrom)) {
      security_message(port:port, proto:"udp");
      exit(0);
    }
  }
}

exit(99);